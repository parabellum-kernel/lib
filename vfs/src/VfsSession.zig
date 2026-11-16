const std = @import("std");
const Crypto = @import("Crypto.zig");
const CatalogPort = @import("CatalogPort.zig");
const BlobStorePort = @import("BlobStorePort.zig");
const PoolAllocator = @import("PoolAllocator.zig");
const PartStream = @import("PartStream.zig");
const Packer = @import("Packer.zig");
const SyncCoordinator = @import("SyncCoordinator.zig");

/// Backend-agnostic VFS session coordinating storage pools, `RangeCache`, and encrypted catalog (`ARCH-037B`).
const VfsSession = @This();

pub const WriteOptions = struct {
    max_part_size_bytes: u64 = 2048 * 1024 * 1024,
    adaptive_compression: bool = true,
    mime_type: ?[]const u8 = null,
    upload_policy: ?PoolAllocator.UploadPolicy = null,
};

pub const NodeQuotaInfo = struct {
    node_id: []const u8,
    total_bytes: u64,
    used_bytes: u64,
    reserved_headroom_bytes: u64,
    active_leased_bytes: u64,
    available_bytes: u64,
    status: CatalogPort.AccountStatus,
    last_quota_sync_at: i64,
};

pub const PoolQuotaSummary = struct {
    total_bytes: u64,
    used_bytes: u64,
    reserved_headroom_bytes: u64,
    active_leased_bytes: u64,
    available_bytes: u64,
    nodes: []NodeQuotaInfo,

    pub fn deinit(self: *PoolQuotaSummary, allocator: std.mem.Allocator) void {
        for (self.nodes) |n| allocator.free(n.node_id);
        allocator.free(self.nodes);
    }
};

pub const WriteOutcome = struct {
    extent_count: usize,
    new_etag: ?[]u8,
    new_epoch: u64,

    pub fn deinit(self: *WriteOutcome, allocator: std.mem.Allocator) void {
        if (self.new_etag) |e| allocator.free(e);
    }
};

pub const PackWriteOutcome = struct {
    pack_count: usize,
    file_count: usize,
    new_etag: ?[]u8,
    new_epoch: u64,

    pub fn deinit(self: *PackWriteOutcome, allocator: std.mem.Allocator) void {
        if (self.new_etag) |e| allocator.free(e);
    }
};

pub const CommitOutcome = struct {
    new_etag: ?[]u8,
    new_epoch: u64,

    pub fn deinit(self: *CommitOutcome, allocator: std.mem.Allocator) void {
        if (self.new_etag) |e| allocator.free(e);
    }
};

pub const GcOutcome = struct {
    deleted_count: usize,
    new_etag: ?[]u8,
    new_epoch: u64,

    pub fn deinit(self: *GcOutcome, allocator: std.mem.Allocator) void {
        if (self.new_etag) |e| allocator.free(e);
    }
};

pub const RefreshOutcome = struct {
    updated: bool,
    new_etag: ?[]u8,
    new_epoch: u64,

    pub fn deinit(self: *RefreshOutcome, allocator: std.mem.Allocator) void {
        if (self.new_etag) |e| allocator.free(e);
    }
};

alloc: std.mem.Allocator,
range_cache: PartStream.RangeCache,

pub fn init(alloc: std.mem.Allocator) VfsSession {
    return initWithCache(alloc, 64 * 1024 * 1024);
}

pub fn initWithCache(alloc: std.mem.Allocator, read_cache_max_bytes: usize) VfsSession {
    return .{
        .alloc = alloc,
        .range_cache = PartStream.RangeCache.init(alloc, read_cache_max_bytes),
    };
}

pub fn deinit(self: *VfsSession) void {
    self.range_cache.deinit();
}

fn findPrimaryCatalogNode(nodes: []const CatalogPort.StorageNodeEntry) []const u8 {
    for (nodes) |n| {
        if (n.catalog_role == .primary) return n.node_id;
    }
    return nodes[0].node_id;
}

fn buildQuotas(
    self: *VfsSession,
    catalog: CatalogPort,
    nodes: []const CatalogPort.StorageNodeEntry,
    now_unix_s: i64,
) ![]PoolAllocator.ServiceAccountQuota {
    const active_leases = try catalog.listActiveLeases(self.alloc, now_unix_s);
    defer self.alloc.free(active_leases);

    const quotas = try self.alloc.alloc(PoolAllocator.ServiceAccountQuota, nodes.len);
    for (nodes, 0..) |node, i| {
        var leased: u64 = 0;
        for (active_leases) |l| {
            if (std.mem.eql(u8, l.node_id, node.node_id)) leased +|= l.reserved_bytes;
        }
        quotas[i] = .{
            .sa_index = i,
            .sa_id = node.node_id,
            .total_bytes = node.quota_limit_bytes,
            .used_bytes = node.quota_used_bytes,
            .reserved_headroom_bytes = node.catalog_headroom_bytes,
            .active_leased_bytes = leased,
        };
    }
    return quotas;
}

fn recordLocalQuotaUsage(
    allocator: std.mem.Allocator,
    catalog: CatalogPort,
    node_id: []const u8,
    added_bytes: u64,
) !void {
    const nodes = try catalog.listStorageNodes(allocator);
    defer allocator.free(nodes);
    for (nodes) |node| {
        if (std.mem.eql(u8, node.node_id, node_id)) {
            var updated = node;
            updated.quota_used_bytes +|= added_bytes;
            try catalog.putStorageNode(updated);
            return;
        }
    }
}

fn commitCatalogOps(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    ops: []const CatalogPort.CatalogDeltaOp,
) !CommitOutcome {
    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);
    if (nodes.len == 0) return error.NoStorageNodes;

    const primary_node = findPrimaryCatalogNode(nodes);
    var commit_res = try SyncCoordinator.commitDeltaWithRetry(
        self.alloc,
        io,
        store,
        primary_node,
        catalog_object_id,
        initial_etag,
        catalog,
        vmk,
        vault_id,
        ops,
        5,
    );
    errdefer commit_res.deinit(self.alloc);

    return .{
        .new_etag = commit_res.new_etag,
        .new_epoch = commit_res.new_epoch,
    };
}

/// Encrypts, stripes across healthy nodes in the pool, uploads `.part` blobs via `store`,
/// and commits the new inode + extents to the remote catalog with optimistic CAS.
pub fn writeFile(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    parent_id: ?[]const u8,
    name: []const u8,
    inode_id: []const u8,
    inode_ulid: [16]u8,
    plaintext: []const u8,
    opts: WriteOptions,
    now_unix_s: i64,
) !WriteOutcome {
    var file_dek: [Crypto.KEY_LEN]u8 = undefined;
    io.random(&file_dek);
    const wrapped_dek = Crypto.wrapKeyWithNonce(io, vmk, file_dek, &inode_ulid);

    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);
    if (nodes.len == 0) return error.NoStorageNodes;

    const quotas = try self.buildQuotas(catalog, nodes, now_unix_s);
    defer self.alloc.free(quotas);

    var default_pol = PoolAllocator.MostAvailablePolicy{};
    const policy = opts.upload_policy orelse default_pol.policy();
    const plan = try PoolAllocator.planStripedAllocationWithPolicy(
        self.alloc,
        quotas,
        plaintext.len,
        opts.max_part_size_bytes,
        policy,
    );
    defer self.alloc.free(plan);

    const blob_names = try self.alloc.alloc([]u8, plan.len);
    const obj_ids = try self.alloc.alloc([]u8, plan.len);
    var built: usize = 0;
    defer {
        for (0..built) |idx| {
            self.alloc.free(blob_names[idx]);
            self.alloc.free(obj_ids[idx]);
        }
        self.alloc.free(blob_names);
        self.alloc.free(obj_ids);
    }

    const ops = try self.alloc.alloc(CatalogPort.CatalogDeltaOp, 1 + plan.len);
    defer self.alloc.free(ops);

    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext, &sha256, .{});

    ops[0] = .{ .put_inode = .{
        .inode_id = inode_id,
        .parent_id = parent_id,
        .name = name,
        .kind = .file,
        .logical_size = plaintext.len,
        .compression_mode = if (opts.adaptive_compression) "per_page_adaptive" else "none",
        .file_dek_wrapped = &wrapped_dek,
        .content_sha256 = sha256,
        .mime_type = opts.mime_type,
        .mtime = now_unix_s,
    } };

    for (plan, 0..) |ext, part_idx| {
        const start: usize = @intCast(ext.logical_offset);
        const len: usize = @intCast(ext.allocated_bytes);
        const part_plain = plaintext[start .. start + len];

        const encoded = try PartStream.encodePart(
            self.alloc,
            io,
            file_dek,
            inode_ulid,
            @intCast(part_idx),
            part_plain,
            opts.adaptive_compression,
        );
        defer self.alloc.free(encoded);

        const remote_name = try std.fmt.allocPrint(self.alloc, "{s}_{d}.part", .{ inode_id, part_idx });
        errdefer self.alloc.free(remote_name);

        const uploaded = try store.putObject(self.alloc, ext.sa_id, remote_name, encoded);
        if (uploaded.etag) |e| self.alloc.free(e);

        blob_names[built] = remote_name;
        obj_ids[built] = uploaded.object_id;
        built += 1;

        ops[1 + part_idx] = .{ .put_extent = .{
            .inode_id = inode_id,
            .part_index = @intCast(part_idx),
            .logical_offset = ext.logical_offset,
            .logical_len = ext.allocated_bytes,
            .node_id = ext.sa_id,
            .remote_object_id = uploaded.object_id,
            .remote_blob_name = remote_name,
            .physical_size = encoded.len,
        } };
    }

    var commit_out = try self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, ops);
    errdefer commit_out.deinit(self.alloc);

    for (ops[1..]) |op| {
        if (op == .put_extent) {
            try recordLocalQuotaUsage(self.alloc, catalog, op.put_extent.node_id, op.put_extent.physical_size);
        }
    }

    return .{
        .extent_count = plan.len,
        .new_etag = commit_out.new_etag,
        .new_epoch = commit_out.new_epoch,
    };
}

/// Encrypts and packs multiple small files into `.pack` blobs, uploads each pack, and commits via CAS.
pub fn writePackedFiles(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    inputs: []const Packer.SmallFileInput,
    pack_config: Packer.PackConfig,
    now_unix_s: i64,
) !PackWriteOutcome {
    if (inputs.len == 0) {
        return .{
            .pack_count = 0,
            .file_count = 0,
            .new_etag = if (initial_etag) |e| try self.alloc.dupe(u8, e) else null,
            .new_epoch = catalog.getMeta().vfs_epoch,
        };
    }

    const batches = try Packer.buildPacks(self.alloc, io, vmk, inputs, pack_config);
    defer {
        for (batches) |*b| b.deinit(self.alloc);
        self.alloc.free(batches);
    }

    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);
    if (nodes.len == 0) return error.NoStorageNodes;

    const quotas = try self.buildQuotas(catalog, nodes, now_unix_s);
    defer self.alloc.free(quotas);

    const blob_names = try self.alloc.alloc([]u8, batches.len);
    const obj_ids = try self.alloc.alloc([]u8, batches.len);
    var built: usize = 0;
    defer {
        for (0..built) |idx| {
            self.alloc.free(blob_names[idx]);
            self.alloc.free(obj_ids[idx]);
        }
        self.alloc.free(blob_names);
        self.alloc.free(obj_ids);
    }

    var total_files: usize = 0;
    for (batches) |b| total_files += b.items.len;

    const ops = try self.alloc.alloc(CatalogPort.CatalogDeltaOp, total_files * 2);
    defer self.alloc.free(ops);

    var default_pol = PoolAllocator.MostAvailablePolicy{};
    const policy = pack_config.upload_policy orelse default_pol.policy();

    var op_idx: usize = 0;
    for (batches) |batch| {
        const chosen_idx = policy.selectAccount(quotas, batch.blob.len) orelse return error.InsufficientPoolQuota;
        const node_id = quotas[chosen_idx].sa_id;
        quotas[chosen_idx].used_bytes +|= batch.blob.len;

        const remote_name = try std.fmt.allocPrint(self.alloc, "pack_{s}.pack", .{batch.items[0].inode_id});
        errdefer self.alloc.free(remote_name);

        const uploaded = try store.putObject(self.alloc, node_id, remote_name, batch.blob);
        if (uploaded.etag) |e| self.alloc.free(e);

        blob_names[built] = remote_name;
        obj_ids[built] = uploaded.object_id;
        built += 1;

        for (batch.items) |*item| {
            ops[op_idx] = .{ .put_inode = .{
                .inode_id = item.inode_id,
                .parent_id = item.parent_id,
                .name = item.name,
                .kind = .file,
                .logical_size = item.logical_size,
                .compression_mode = item.compression_mode,
                .file_dek_wrapped = &item.wrapped_dek,
                .content_sha256 = item.content_sha256,
                .mime_type = item.mime_type,
                .mtime = now_unix_s,
            } };
            op_idx += 1;

            ops[op_idx] = .{ .put_extent = .{
                .inode_id = item.inode_id,
                .part_index = 0,
                .logical_offset = 0,
                .logical_len = item.logical_size,
                .node_id = node_id,
                .remote_object_id = uploaded.object_id,
                .remote_blob_name = remote_name,
                .physical_size = batch.blob.len,
                .phys_part_offset = item.phys_part_offset,
                .phys_part_len = item.phys_part_len,
            } };
            op_idx += 1;
        }
    }

    var commit_out = try self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, ops);
    errdefer commit_out.deinit(self.alloc);

    for (batches) |batch| {
        const first_ext = for (ops) |op| {
            if (op == .put_extent and std.mem.eql(u8, op.put_extent.inode_id, batch.items[0].inode_id)) break op.put_extent;
        } else continue;
        try recordLocalQuotaUsage(self.alloc, catalog, first_ext.node_id, batch.blob.len);
    }

    return .{
        .pack_count = batches.len,
        .file_count = total_files,
        .new_etag = commit_out.new_etag,
        .new_epoch = commit_out.new_epoch,
    };
}

pub fn mkdir(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    parent_id: ?[]const u8,
    name: []const u8,
    inode_id: []const u8,
    now_unix_s: i64,
) !CommitOutcome {
    if (catalog.findInodeByName(parent_id, name) != null) return error.AlreadyExists;
    const ops = [_]CatalogPort.CatalogDeltaOp{
        .{ .put_inode = .{
            .inode_id = inode_id,
            .parent_id = parent_id,
            .name = name,
            .kind = .dir,
            .mtime = now_unix_s,
        } },
    };
    return self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, &ops);
}

pub fn rename(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    inode_id: []const u8,
    new_parent_id: ?[]const u8,
    new_name: []const u8,
    now_unix_s: i64,
) !CommitOutcome {
    const existing = catalog.getInode(inode_id) orelse return error.InodeNotFound;
    if (catalog.findInodeByName(new_parent_id, new_name) != null) return error.AlreadyExists;

    var updated = existing;
    updated.parent_id = new_parent_id;
    updated.name = new_name;
    updated.mtime = now_unix_s;

    const ops = [_]CatalogPort.CatalogDeltaOp{
        .{ .put_inode = updated },
    };
    return self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, &ops);
}

pub fn deleteInodeAndMarkGc(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    inode_id: []const u8,
    now_unix_s: i64,
) !CommitOutcome {
    const existing = catalog.getInode(inode_id) orelse return error.InodeNotFound;
    if (existing.kind == .dir) {
        const children = try catalog.listChildren(self.alloc, inode_id);
        defer self.alloc.free(children);
        if (children.len > 0) return error.DirectoryNotEmpty;
    }

    const extents = try catalog.listExtents(self.alloc, inode_id);
    defer self.alloc.free(extents);

    var ops = std.ArrayListUnmanaged(CatalogPort.CatalogDeltaOp).empty;
    defer ops.deinit(self.alloc);
    var gc_ids = std.ArrayListUnmanaged([]u8).empty;
    defer {
        for (gc_ids.items) |id| self.alloc.free(id);
        gc_ids.deinit(self.alloc);
    }

    for (extents, 0..) |ext, i| {
        const is_standalone = (ext.phys_part_len == 0 or ext.phys_part_len == ext.physical_size);
        if (!is_standalone) continue;

        const gc_id = try std.fmt.allocPrint(self.alloc, "{s}:{d}:{d}", .{ inode_id, i, now_unix_s });
        try gc_ids.append(self.alloc, gc_id);
        try ops.append(self.alloc, .{ .mark_gc = .{
            .gc_id = gc_id,
            .node_id = ext.node_id,
            .remote_object_id = ext.remote_object_id,
            .marked_at = now_unix_s,
        } });
    }
    try ops.append(self.alloc, .{ .delete_inode = inode_id });

    return self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, ops.items);
}

pub fn collectGarbage(
    self: *VfsSession,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
) !GcOutcome {
    const pending = try catalog.listPendingGc(self.alloc);
    defer self.alloc.free(pending);

    if (pending.len == 0) {
        return .{
            .deleted_count = 0,
            .new_etag = if (initial_etag) |e| try self.alloc.dupe(u8, e) else null,
            .new_epoch = catalog.getMeta().vfs_epoch,
        };
    }

    const ops = try self.alloc.alloc(CatalogPort.CatalogDeltaOp, pending.len);
    defer self.alloc.free(ops);

    var deleted_count: usize = 0;
    for (pending) |entry| {
        try store.deleteObject(self.alloc, entry.node_id, entry.remote_object_id);
        ops[deleted_count] = .{ .delete_gc = entry.gc_id };
        deleted_count += 1;
    }

    var commit_out = try self.commitCatalogOps(io, store, catalog, vmk, vault_id, catalog_object_id, initial_etag, ops[0..deleted_count]);
    errdefer commit_out.deinit(self.alloc);

    return .{
        .deleted_count = deleted_count,
        .new_etag = commit_out.new_etag,
        .new_epoch = commit_out.new_epoch,
    };
}

pub fn getQuotas(
    self: *VfsSession,
    catalog: CatalogPort,
    now_unix_s: i64,
) !PoolQuotaSummary {
    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);
    const active_leases = try catalog.listActiveLeases(self.alloc, now_unix_s);
    defer self.alloc.free(active_leases);

    const out_nodes = try self.alloc.alloc(NodeQuotaInfo, nodes.len);
    var built: usize = 0;
    errdefer {
        for (out_nodes[0..built]) |n| self.alloc.free(n.node_id);
        self.alloc.free(out_nodes);
    }

    var total_bytes: u64 = 0;
    var used_bytes: u64 = 0;
    var reserved_headroom_bytes: u64 = 0;
    var active_leased_bytes: u64 = 0;
    var available_bytes: u64 = 0;

    for (nodes, 0..) |node, i| {
        var leased: u64 = 0;
        for (active_leases) |l| {
            if (std.mem.eql(u8, l.node_id, node.node_id)) leased +|= l.reserved_bytes;
        }
        const q = PoolAllocator.ServiceAccountQuota{
            .sa_index = i,
            .sa_id = node.node_id,
            .total_bytes = node.quota_limit_bytes,
            .used_bytes = node.quota_used_bytes,
            .reserved_headroom_bytes = node.catalog_headroom_bytes,
            .active_leased_bytes = leased,
        };
        const avail = q.availableBytes();

        out_nodes[built] = .{
            .node_id = try self.alloc.dupe(u8, node.node_id),
            .total_bytes = node.quota_limit_bytes,
            .used_bytes = node.quota_used_bytes,
            .reserved_headroom_bytes = node.catalog_headroom_bytes,
            .active_leased_bytes = leased,
            .available_bytes = avail,
            .status = node.status,
            .last_quota_sync_at = node.last_quota_sync_at,
        };
        built += 1;

        total_bytes +|= node.quota_limit_bytes;
        used_bytes +|= node.quota_used_bytes;
        reserved_headroom_bytes +|= node.catalog_headroom_bytes;
        active_leased_bytes +|= leased;
        available_bytes +|= avail;
    }

    return .{
        .total_bytes = total_bytes,
        .used_bytes = used_bytes,
        .reserved_headroom_bytes = reserved_headroom_bytes,
        .active_leased_bytes = active_leased_bytes,
        .available_bytes = available_bytes,
        .nodes = out_nodes,
    };
}

pub fn syncQuotasFromRemote(
    self: *VfsSession,
    store: BlobStorePort,
    catalog: CatalogPort,
    now_unix_s: i64,
) !PoolQuotaSummary {
    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);

    for (nodes) |node| {
        const q = try store.getQuota(self.alloc, node.node_id);
        var updated = node;
        updated.quota_limit_bytes = q.limit_bytes;
        updated.quota_used_bytes = q.used_bytes;
        updated.last_quota_sync_at = now_unix_s;
        try catalog.putStorageNode(updated);
    }

    return self.getQuotas(catalog, now_unix_s);
}

pub fn refreshCatalog(
    self: *VfsSession,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
) !RefreshOutcome {
    const nodes = try catalog.listStorageNodes(self.alloc);
    defer self.alloc.free(nodes);
    if (nodes.len == 0) return error.NoStorageNodes;

    const primary_node = findPrimaryCatalogNode(nodes);
    var dl = try store.getObject(self.alloc, primary_node, catalog_object_id);
    errdefer dl.deinit(self.alloc);

    if (initial_etag != null and dl.etag != null and std.mem.eql(u8, initial_etag.?, dl.etag.?)) {
        const kept_etag = try self.alloc.dupe(u8, initial_etag.?);
        dl.deinit(self.alloc);
        return .{
            .updated = false,
            .new_etag = kept_etag,
            .new_epoch = catalog.getMeta().vfs_epoch,
        };
    }

    try SyncCoordinator.openCatalogSnapshot(self.alloc, catalog, vmk, vault_id, dl.data);

    const new_etag = dl.etag;
    dl.etag = null;
    dl.deinit(self.alloc);

    return .{
        .updated = true,
        .new_etag = new_etag,
        .new_epoch = catalog.getMeta().vfs_epoch,
    };
}

const StoreRangeSource = struct {
    store: BlobStorePort,
    node_id: []const u8,
    object_id: []const u8,
    base_offset: u64 = 0,

    fn readRange(ptr: *anyopaque, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) anyerror![]u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return self.store.getRange(
            allocator,
            self.node_id,
            self.object_id,
            self.base_offset + start,
            self.base_offset + end_inclusive,
        );
    }

    fn byteReader(self: *StoreRangeSource) PartStream.ByteRangeReader {
        return .{ .ptr = self, .readRangeFn = readRange };
    }
};

pub fn readFileAt(
    self: *VfsSession,
    store: BlobStorePort,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    inode_id: []const u8,
    inode_ulid: [16]u8,
    offset: u64,
    out: []u8,
) !usize {
    const inode = catalog.getInode(inode_id) orelse return error.InodeNotFound;
    if (offset >= inode.logical_size or out.len == 0) return 0;

    const wrapped_dek = inode.file_dek_wrapped orelse return error.MissingFileDek;
    if (wrapped_dek.len != Crypto.WRAPPED_KEY_WITH_NONCE_LEN) return error.InvalidWrappedDek;
    const file_dek = try Crypto.unwrapKeyWithNonce(
        vmk,
        wrapped_dek[0..Crypto.WRAPPED_KEY_WITH_NONCE_LEN].*,
        &inode_ulid,
    );

    const extents = try catalog.listExtents(self.alloc, inode_id);
    defer self.alloc.free(extents);

    const total_to_read: usize = @intCast(@min(@as(u64, out.len), inode.logical_size - offset));
    var out_pos: usize = 0;

    for (extents) |ext| {
        const ext_end = ext.logical_offset + ext.logical_len;
        const req_start = offset + out_pos;
        if (req_start >= ext_end) continue;
        if (ext.logical_offset >= offset + total_to_read) break;

        var src = StoreRangeSource{
            .store = store,
            .node_id = ext.node_id,
            .object_id = ext.remote_object_id,
            .base_offset = ext.phys_part_offset,
        };
        var cached_src = PartStream.CachedRangeReader{
            .inner = src.byteReader(),
            .cache = &self.range_cache,
            .file_id = ext.remote_object_id,
            .base_offset = ext.phys_part_offset,
        };
        var reader = try PartStream.Reader.open(
            self.alloc,
            cached_src.byteReader(),
            file_dek,
            inode_ulid,
            ext.part_index,
            ext.logical_len,
        );
        defer reader.deinit();

        const local_off = req_start - ext.logical_offset;
        const remain_in_ext: usize = @intCast(ext.logical_len - local_off);
        const chunk_len = @min(remain_in_ext, total_to_read - out_pos);

        const n = try reader.readAt(local_off, out[out_pos..][0..chunk_len]);
        out_pos += n;
        if (out_pos >= total_to_read) break;
    }

    return out_pos;
}
