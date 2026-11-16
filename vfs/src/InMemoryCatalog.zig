const std = @import("std");
const CatalogPort = @import("CatalogPort.zig");

const VfsMeta = CatalogPort.VfsMeta;
const VaultKeySlot = CatalogPort.VaultKeySlot;
const CatalogRole = CatalogPort.CatalogRole;
const AccountStatus = CatalogPort.AccountStatus;
const StorageNodeEntry = CatalogPort.StorageNodeEntry;
const LeasePurpose = CatalogPort.LeasePurpose;
const UploadLease = CatalogPort.UploadLease;
const InodeKind = CatalogPort.InodeKind;
const Inode = CatalogPort.Inode;
const InodeExtent = CatalogPort.InodeExtent;
const PendingGcEntry = CatalogPort.PendingGcEntry;

/// Pure-Zig in-memory `CatalogPort` implementation with binary `GDRVCAT1` snapshot serialization.
const InMemoryCatalog = @This();

allocator: std.mem.Allocator,
meta: VfsMeta = .{},
owned_meta_strings: [4]?[]u8 = .{ null, null, null, null },

key_slots: std.ArrayListUnmanaged(OwnedKeySlot) = .empty,
service_accounts: std.ArrayListUnmanaged(OwnedServiceAccount) = .empty,
leases: std.ArrayListUnmanaged(OwnedLease) = .empty,
inodes: std.ArrayListUnmanaged(OwnedInode) = .empty,
extents: std.ArrayListUnmanaged(OwnedExtent) = .empty,
pending_gc: std.ArrayListUnmanaged(OwnedGc) = .empty,

const OwnedKeySlot = struct {
    slot_id: []u8,
    label: []u8,
    kem_alg: []u8,
    aead_alg: []u8,
    public_key: []u8,
    kem_ciphertext: []u8,
    vmk_wrapped: []u8,
    created_at: i64,

    fn view(self: OwnedKeySlot) VaultKeySlot {
        return .{
            .slot_id = self.slot_id,
            .label = self.label,
            .kem_alg = self.kem_alg,
            .aead_alg = self.aead_alg,
            .public_key = self.public_key,
            .kem_ciphertext = self.kem_ciphertext,
            .vmk_wrapped = self.vmk_wrapped,
            .created_at = self.created_at,
        };
    }
    fn deinit(self: *OwnedKeySlot, a: std.mem.Allocator) void {
        a.free(self.slot_id);
        a.free(self.label);
        a.free(self.kem_alg);
        a.free(self.aead_alg);
        a.free(self.public_key);
        a.free(self.kem_ciphertext);
        a.free(self.vmk_wrapped);
    }
};

const OwnedServiceAccount = struct {
    node_id: []u8,
    credentials_wrapped: []u8,
    quota_limit_bytes: u64,
    quota_used_bytes: u64,
    catalog_headroom_bytes: u64,
    catalog_role: CatalogRole,
    status: AccountStatus,
    last_quota_sync_at: i64,

    fn view(self: OwnedServiceAccount) StorageNodeEntry {
        return .{
            .node_id = self.node_id,
            .credentials_wrapped = self.credentials_wrapped,
            .quota_limit_bytes = self.quota_limit_bytes,
            .quota_used_bytes = self.quota_used_bytes,
            .catalog_headroom_bytes = self.catalog_headroom_bytes,
            .catalog_role = self.catalog_role,
            .status = self.status,
            .last_quota_sync_at = self.last_quota_sync_at,
        };
    }
    fn deinit(self: *OwnedServiceAccount, a: std.mem.Allocator) void {
        a.free(self.node_id);
        a.free(self.credentials_wrapped);
    }
};

const OwnedLease = struct {
    lease_id: []u8,
    device_id: []u8,
    node_id: []u8,
    reserved_bytes: u64,
    purpose: LeasePurpose,
    expires_at: i64,

    fn view(self: OwnedLease) UploadLease {
        return .{
            .lease_id = self.lease_id,
            .device_id = self.device_id,
            .node_id = self.node_id,
            .reserved_bytes = self.reserved_bytes,
            .purpose = self.purpose,
            .expires_at = self.expires_at,
        };
    }
    fn deinit(self: *OwnedLease, a: std.mem.Allocator) void {
        a.free(self.lease_id);
        a.free(self.device_id);
        a.free(self.node_id);
    }
};

const OwnedInode = struct {
    inode_id: []u8,
    parent_id: ?[]u8,
    name: []u8,
    kind: InodeKind,
    logical_size: u64,
    compression_mode: []u8,
    file_dek_wrapped: ?[]u8,
    content_sha256: ?[32]u8,
    mime_type: ?[]u8,
    mtime: i64,

    fn view(self: OwnedInode) Inode {
        return .{
            .inode_id = self.inode_id,
            .parent_id = self.parent_id,
            .name = self.name,
            .kind = self.kind,
            .logical_size = self.logical_size,
            .compression_mode = self.compression_mode,
            .file_dek_wrapped = self.file_dek_wrapped,
            .content_sha256 = self.content_sha256,
            .mime_type = self.mime_type,
            .mtime = self.mtime,
        };
    }
    fn deinit(self: *OwnedInode, a: std.mem.Allocator) void {
        a.free(self.inode_id);
        if (self.parent_id) |p| a.free(p);
        a.free(self.name);
        a.free(self.compression_mode);
        if (self.file_dek_wrapped) |d| a.free(d);
        if (self.mime_type) |m| a.free(m);
    }
};

const OwnedExtent = struct {
    inode_id: []u8,
    part_index: u32,
    logical_offset: u64,
    logical_len: u64,
    node_id: []u8,
    remote_object_id: []u8,
    remote_blob_name: []u8,
    physical_size: u64,
    phys_part_offset: u64,
    phys_part_len: u64,

    fn view(self: OwnedExtent) InodeExtent {
        return .{
            .inode_id = self.inode_id,
            .part_index = self.part_index,
            .logical_offset = self.logical_offset,
            .logical_len = self.logical_len,
            .node_id = self.node_id,
            .remote_object_id = self.remote_object_id,
            .remote_blob_name = self.remote_blob_name,
            .physical_size = self.physical_size,
            .phys_part_offset = self.phys_part_offset,
            .phys_part_len = self.phys_part_len,
        };
    }
    fn deinit(self: *OwnedExtent, a: std.mem.Allocator) void {
        a.free(self.inode_id);
        a.free(self.node_id);
        a.free(self.remote_object_id);
        a.free(self.remote_blob_name);
    }
};

const OwnedGc = struct {
    gc_id: []u8,
    node_id: []u8,
    remote_object_id: []u8,
    marked_at: i64,

    fn view(self: OwnedGc) PendingGcEntry {
        return .{
            .gc_id = self.gc_id,
            .node_id = self.node_id,
            .remote_object_id = self.remote_object_id,
            .marked_at = self.marked_at,
        };
    }
    fn deinit(self: *OwnedGc, a: std.mem.Allocator) void {
        a.free(self.gc_id);
        a.free(self.node_id);
        a.free(self.remote_object_id);
    }
};

pub fn init(allocator: std.mem.Allocator) InMemoryCatalog {
    return .{ .allocator = allocator };
}

pub fn clear(self: *InMemoryCatalog) void {
    for (&self.owned_meta_strings) |*slot| {
        if (slot.*) |s| {
            self.allocator.free(s);
            slot.* = null;
        }
    }
    self.meta = .{};

    for (self.key_slots.items) |*it| it.deinit(self.allocator);
    self.key_slots.clearRetainingCapacity();
    for (self.service_accounts.items) |*it| it.deinit(self.allocator);
    self.service_accounts.clearRetainingCapacity();
    for (self.leases.items) |*it| it.deinit(self.allocator);
    self.leases.clearRetainingCapacity();
    for (self.inodes.items) |*it| it.deinit(self.allocator);
    self.inodes.clearRetainingCapacity();
    for (self.extents.items) |*it| it.deinit(self.allocator);
    self.extents.clearRetainingCapacity();
    for (self.pending_gc.items) |*it| it.deinit(self.allocator);
    self.pending_gc.clearRetainingCapacity();
}

pub fn deinit(self: *InMemoryCatalog) void {
    self.clear();
    self.key_slots.deinit(self.allocator);
    self.service_accounts.deinit(self.allocator);
    self.leases.deinit(self.allocator);
    self.inodes.deinit(self.allocator);
    self.extents.deinit(self.allocator);
    self.pending_gc.deinit(self.allocator);
}

pub fn port(self: *InMemoryCatalog) CatalogPort {
    return .{ .ptr = self, .vtable = &VTABLE };
}

const VTABLE = CatalogPort.VTable{
    .getMeta = getMetaImpl,
    .setMeta = setMetaImpl,
    .putKeySlot = putKeySlotImpl,
    .getKeySlot = getKeySlotImpl,
    .deleteKeySlot = deleteKeySlotImpl,
    .putStorageNode = putStorageNodeImpl,
    .listStorageNodes = listStorageNodesImpl,
    .putLease = putLeaseImpl,
    .deleteLease = deleteLeaseImpl,
    .listActiveLeases = listActiveLeasesImpl,
    .pruneExpiredLeases = pruneExpiredLeasesImpl,
    .putInode = putInodeImpl,
    .getInode = getInodeImpl,
    .findInodeByName = findInodeByNameImpl,
    .listChildren = listChildrenImpl,
    .deleteInode = deleteInodeImpl,
    .putExtent = putExtentImpl,
    .listExtents = listExtentsImpl,
    .markGc = markGcImpl,
    .listPendingGc = listPendingGcImpl,
    .deleteGc = deleteGcImpl,
    .exportSnapshot = exportSnapshotImpl,
    .importSnapshot = importSnapshotImpl,
};

fn getMetaImpl(ptr: *anyopaque) VfsMeta {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    return self.meta;
}

fn setMetaImpl(ptr: *anyopaque, meta: VfsMeta) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    const d0 = try self.allocator.dupe(u8, meta.last_writer_device_id);
    errdefer self.allocator.free(d0);
    const d1 = try self.allocator.dupe(u8, meta.last_writer_sdk_semver);
    errdefer self.allocator.free(d1);
    const d2 = try self.allocator.dupe(u8, meta.last_observed_api_id);
    errdefer self.allocator.free(d2);
    const d3 = try self.allocator.dupe(u8, meta.last_observed_api_revision);

    for (&self.owned_meta_strings) |*slot| {
        if (slot.*) |s| self.allocator.free(s);
    }
    self.owned_meta_strings = .{ d0, d1, d2, d3 };
    self.meta = .{
        .schema_version = meta.schema_version,
        .vfs_epoch = meta.vfs_epoch,
        .last_writer_device_id = d0,
        .last_writer_sdk_semver = d1,
        .last_observed_api_id = d2,
        .last_observed_api_revision = d3,
    };
}

fn putKeySlotImpl(ptr: *anyopaque, slot: VaultKeySlot) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    _ = deleteKeySlotImpl(ptr, slot.slot_id);
    try self.key_slots.append(self.allocator, .{
        .slot_id = try self.allocator.dupe(u8, slot.slot_id),
        .label = try self.allocator.dupe(u8, slot.label),
        .kem_alg = try self.allocator.dupe(u8, slot.kem_alg),
        .aead_alg = try self.allocator.dupe(u8, slot.aead_alg),
        .public_key = try self.allocator.dupe(u8, slot.public_key),
        .kem_ciphertext = try self.allocator.dupe(u8, slot.kem_ciphertext),
        .vmk_wrapped = try self.allocator.dupe(u8, slot.vmk_wrapped),
        .created_at = slot.created_at,
    });
}

fn getKeySlotImpl(ptr: *anyopaque, slot_id: []const u8) ?VaultKeySlot {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.key_slots.items) |it| {
        if (std.mem.eql(u8, it.slot_id, slot_id)) return it.view();
    }
    return null;
}

fn deleteKeySlotImpl(ptr: *anyopaque, slot_id: []const u8) bool {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.key_slots.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.slot_id, slot_id)) {
            it.deinit(self.allocator);
            _ = self.key_slots.swapRemove(i);
            return true;
        }
    }
    return false;
}

fn putStorageNodeImpl(ptr: *anyopaque, sa: StorageNodeEntry) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    const new_id = try self.allocator.dupe(u8, sa.node_id);
    errdefer self.allocator.free(new_id);
    const new_creds = try self.allocator.dupe(u8, sa.credentials_wrapped);
    errdefer self.allocator.free(new_creds);

    for (self.service_accounts.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.node_id, new_id)) {
            it.deinit(self.allocator);
            _ = self.service_accounts.swapRemove(i);
            break;
        }
    }
    try self.service_accounts.append(self.allocator, .{
        .node_id = new_id,
        .credentials_wrapped = new_creds,
        .quota_limit_bytes = sa.quota_limit_bytes,
        .quota_used_bytes = sa.quota_used_bytes,
        .catalog_headroom_bytes = sa.catalog_headroom_bytes,
        .catalog_role = sa.catalog_role,
        .status = sa.status,
        .last_quota_sync_at = sa.last_quota_sync_at,
    });
}

fn listStorageNodesImpl(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]StorageNodeEntry {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    const out = try allocator.alloc(StorageNodeEntry, self.service_accounts.items.len);
    for (self.service_accounts.items, 0..) |it, i| out[i] = it.view();
    return out;
}

fn putLeaseImpl(ptr: *anyopaque, lease: UploadLease) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    _ = deleteLeaseImpl(ptr, lease.lease_id);
    try self.leases.append(self.allocator, .{
        .lease_id = try self.allocator.dupe(u8, lease.lease_id),
        .device_id = try self.allocator.dupe(u8, lease.device_id),
        .node_id = try self.allocator.dupe(u8, lease.node_id),
        .reserved_bytes = lease.reserved_bytes,
        .purpose = lease.purpose,
        .expires_at = lease.expires_at,
    });
}

fn deleteLeaseImpl(ptr: *anyopaque, lease_id: []const u8) bool {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.leases.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.lease_id, lease_id)) {
            it.deinit(self.allocator);
            _ = self.leases.swapRemove(i);
            return true;
        }
    }
    return false;
}

fn listActiveLeasesImpl(ptr: *anyopaque, allocator: std.mem.Allocator, now_unix_s: i64) anyerror![]UploadLease {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var count: usize = 0;
    for (self.leases.items) |it| {
        if (it.expires_at > now_unix_s) count += 1;
    }
    const out = try allocator.alloc(UploadLease, count);
    var idx: usize = 0;
    for (self.leases.items) |it| {
        if (it.expires_at > now_unix_s) {
            out[idx] = it.view();
            idx += 1;
        }
    }
    return out;
}

fn pruneExpiredLeasesImpl(ptr: *anyopaque, now_unix_s: i64) usize {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var removed: usize = 0;
    var i: usize = 0;
    while (i < self.leases.items.len) {
        if (self.leases.items[i].expires_at <= now_unix_s) {
            self.leases.items[i].deinit(self.allocator);
            _ = self.leases.swapRemove(i);
            removed += 1;
        } else {
            i += 1;
        }
    }
    return removed;
}

fn putInodeImpl(ptr: *anyopaque, inode: Inode) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var new_entry: OwnedInode = .{
        .inode_id = try self.allocator.dupe(u8, inode.inode_id),
        .parent_id = if (inode.parent_id) |p| try self.allocator.dupe(u8, p) else null,
        .name = try self.allocator.dupe(u8, inode.name),
        .kind = inode.kind,
        .logical_size = inode.logical_size,
        .compression_mode = try self.allocator.dupe(u8, inode.compression_mode),
        .file_dek_wrapped = if (inode.file_dek_wrapped) |d| try self.allocator.dupe(u8, d) else null,
        .content_sha256 = inode.content_sha256,
        .mime_type = if (inode.mime_type) |m| try self.allocator.dupe(u8, m) else null,
        .mtime = inode.mtime,
    };
    errdefer new_entry.deinit(self.allocator);

    for (self.inodes.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.inode_id, new_entry.inode_id)) {
            it.deinit(self.allocator);
            _ = self.inodes.swapRemove(i);
            break;
        }
    }
    try self.inodes.append(self.allocator, new_entry);
}

fn getInodeImpl(ptr: *anyopaque, inode_id: []const u8) ?Inode {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.inodes.items) |it| {
        if (std.mem.eql(u8, it.inode_id, inode_id)) return it.view();
    }
    return null;
}

fn optStrEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a != null and b != null) return std.mem.eql(u8, a.?, b.?);
    return false;
}

fn findInodeByNameImpl(ptr: *anyopaque, parent_id: ?[]const u8, name: []const u8) ?Inode {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.inodes.items) |it| {
        if (optStrEql(it.parent_id, parent_id) and std.mem.eql(u8, it.name, name)) {
            return it.view();
        }
    }
    return null;
}

fn listChildrenImpl(ptr: *anyopaque, allocator: std.mem.Allocator, parent_id: ?[]const u8) anyerror![]Inode {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var out = std.ArrayListUnmanaged(Inode).empty;
    errdefer out.deinit(allocator);
    for (self.inodes.items) |it| {
        if (optStrEql(it.parent_id, parent_id)) {
            try out.append(allocator, it.view());
        }
    }
    return out.toOwnedSlice(allocator);
}

fn deleteInodeImpl(ptr: *anyopaque, inode_id: []const u8) bool {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var found = false;
    for (self.inodes.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.inode_id, inode_id)) {
            it.deinit(self.allocator);
            _ = self.inodes.swapRemove(i);
            found = true;
            break;
        }
    }
    if (found) {
        var i: usize = 0;
        while (i < self.extents.items.len) {
            if (std.mem.eql(u8, self.extents.items[i].inode_id, inode_id)) {
                self.extents.items[i].deinit(self.allocator);
                _ = self.extents.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
    return found;
}

fn putExtentImpl(ptr: *anyopaque, extent: InodeExtent) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.extents.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.inode_id, extent.inode_id) and it.part_index == extent.part_index) {
            it.deinit(self.allocator);
            _ = self.extents.swapRemove(i);
            break;
        }
    }
    try self.extents.append(self.allocator, .{
        .inode_id = try self.allocator.dupe(u8, extent.inode_id),
        .part_index = extent.part_index,
        .logical_offset = extent.logical_offset,
        .logical_len = extent.logical_len,
        .node_id = try self.allocator.dupe(u8, extent.node_id),
        .remote_object_id = try self.allocator.dupe(u8, extent.remote_object_id),
        .remote_blob_name = try self.allocator.dupe(u8, extent.remote_blob_name),
        .physical_size = extent.physical_size,
        .phys_part_offset = extent.phys_part_offset,
        .phys_part_len = extent.phys_part_len,
    });
}

fn listExtentsImpl(ptr: *anyopaque, allocator: std.mem.Allocator, inode_id: []const u8) anyerror![]InodeExtent {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var count: usize = 0;
    for (self.extents.items) |it| {
        if (std.mem.eql(u8, it.inode_id, inode_id)) count += 1;
    }
    const out = try allocator.alloc(InodeExtent, count);
    var idx: usize = 0;
    for (self.extents.items) |it| {
        if (std.mem.eql(u8, it.inode_id, inode_id)) {
            out[idx] = it.view();
            idx += 1;
        }
    }
    std.sort.pdq(InodeExtent, out, {}, struct {
        fn lessThan(_: void, a: InodeExtent, b: InodeExtent) bool {
            return a.part_index < b.part_index;
        }
    }.lessThan);
    return out;
}

fn markGcImpl(ptr: *anyopaque, entry: PendingGcEntry) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    try self.pending_gc.append(self.allocator, .{
        .gc_id = try self.allocator.dupe(u8, entry.gc_id),
        .node_id = try self.allocator.dupe(u8, entry.node_id),
        .remote_object_id = try self.allocator.dupe(u8, entry.remote_object_id),
        .marked_at = entry.marked_at,
    });
}

fn listPendingGcImpl(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]PendingGcEntry {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    const out = try allocator.alloc(PendingGcEntry, self.pending_gc.items.len);
    for (self.pending_gc.items, 0..) |it, i| out[i] = it.view();
    return out;
}

fn deleteGcImpl(ptr: *anyopaque, gc_id: []const u8) bool {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    for (self.pending_gc.items, 0..) |*it, i| {
        if (std.mem.eql(u8, it.gc_id, gc_id)) {
            it.deinit(self.allocator);
            _ = self.pending_gc.swapRemove(i);
            return true;
        }
    }
    return false;
}

fn exportSnapshotImpl(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8 {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    const w = &aw.writer;

    try w.writeAll(&SNAPSHOT_MAGIC);
    try w.writeInt(u32, self.meta.schema_version, .little);
    try w.writeInt(u64, self.meta.vfs_epoch, .little);
    try writeBytes(w, self.meta.last_writer_device_id);
    try writeBytes(w, self.meta.last_writer_sdk_semver);
    try writeBytes(w, self.meta.last_observed_api_id);
    try writeBytes(w, self.meta.last_observed_api_revision);

    try w.writeInt(u32, @intCast(self.key_slots.items.len), .little);
    for (self.key_slots.items) |it| {
        try writeBytes(w, it.slot_id);
        try writeBytes(w, it.label);
        try writeBytes(w, it.kem_alg);
        try writeBytes(w, it.aead_alg);
        try writeBytes(w, it.public_key);
        try writeBytes(w, it.kem_ciphertext);
        try writeBytes(w, it.vmk_wrapped);
        try w.writeInt(i64, it.created_at, .little);
    }

    try w.writeInt(u32, @intCast(self.service_accounts.items.len), .little);
    for (self.service_accounts.items) |it| {
        try writeBytes(w, it.node_id);
        try writeBytes(w, it.credentials_wrapped);
        try w.writeInt(u64, it.quota_limit_bytes, .little);
        try w.writeInt(u64, it.quota_used_bytes, .little);
        try w.writeInt(u64, it.catalog_headroom_bytes, .little);
        try w.writeByte(@intFromEnum(it.catalog_role));
        try w.writeByte(@intFromEnum(it.status));
        try w.writeInt(i64, it.last_quota_sync_at, .little);
    }

    try w.writeInt(u32, @intCast(self.leases.items.len), .little);
    for (self.leases.items) |it| {
        try writeBytes(w, it.lease_id);
        try writeBytes(w, it.device_id);
        try writeBytes(w, it.node_id);
        try w.writeInt(u64, it.reserved_bytes, .little);
        try w.writeByte(@intFromEnum(it.purpose));
        try w.writeInt(i64, it.expires_at, .little);
    }

    try w.writeInt(u32, @intCast(self.inodes.items.len), .little);
    for (self.inodes.items) |it| {
        try writeBytes(w, it.inode_id);
        try writeOptBytes(w, it.parent_id);
        try writeBytes(w, it.name);
        try w.writeByte(@intFromEnum(it.kind));
        try w.writeInt(u64, it.logical_size, .little);
        try writeBytes(w, it.compression_mode);
        try writeOptBytes(w, it.file_dek_wrapped);
        try writeOptBytes(w, if (it.content_sha256) |*h| h else null);
        try writeOptBytes(w, it.mime_type);
        try w.writeInt(i64, it.mtime, .little);
    }

    try w.writeInt(u32, @intCast(self.extents.items.len), .little);
    for (self.extents.items) |it| {
        try writeBytes(w, it.inode_id);
        try w.writeInt(u32, it.part_index, .little);
        try w.writeInt(u64, it.logical_offset, .little);
        try w.writeInt(u64, it.logical_len, .little);
        try writeBytes(w, it.node_id);
        try writeBytes(w, it.remote_object_id);
        try writeBytes(w, it.remote_blob_name);
        try w.writeInt(u64, it.physical_size, .little);
        try w.writeInt(u64, it.phys_part_offset, .little);
        try w.writeInt(u64, it.phys_part_len, .little);
    }

    try w.writeInt(u32, @intCast(self.pending_gc.items.len), .little);
    for (self.pending_gc.items) |it| {
        try writeBytes(w, it.gc_id);
        try writeBytes(w, it.node_id);
        try writeBytes(w, it.remote_object_id);
        try w.writeInt(i64, it.marked_at, .little);
    }

    return aw.toOwnedSlice();
}

fn importSnapshotImpl(ptr: *anyopaque, snapshot_bytes: []const u8) anyerror!void {
    const self: *InMemoryCatalog = @ptrCast(@alignCast(ptr));
    var r: std.Io.Reader = .fixed(snapshot_bytes);

    var magic: [8]u8 = undefined;
    try r.readSliceAll(&magic);
    if (!std.mem.eql(u8, &magic, &SNAPSHOT_MAGIC)) return error.InvalidSnapshotMagic;

    self.clear();
    errdefer self.clear();

    const schema_ver = try r.takeInt(u32, .little);
    const epoch = try r.takeInt(u64, .little);
    const dev_id = try readBytes(&r, self.allocator);
    defer self.allocator.free(dev_id);
    const sdk_ver = try readBytes(&r, self.allocator);
    defer self.allocator.free(sdk_ver);
    const api_id = try readBytes(&r, self.allocator);
    defer self.allocator.free(api_id);
    const api_rev = try readBytes(&r, self.allocator);
    defer self.allocator.free(api_rev);

    try setMetaImpl(ptr, .{
        .schema_version = schema_ver,
        .vfs_epoch = epoch,
        .last_writer_device_id = dev_id,
        .last_writer_sdk_semver = sdk_ver,
        .last_observed_api_id = api_id,
        .last_observed_api_revision = api_rev,
    });

    const n_slots = try r.takeInt(u32, .little);
    for (0..n_slots) |_| {
        try self.key_slots.append(self.allocator, .{
            .slot_id = try readBytes(&r, self.allocator),
            .label = try readBytes(&r, self.allocator),
            .kem_alg = try readBytes(&r, self.allocator),
            .aead_alg = try readBytes(&r, self.allocator),
            .public_key = try readBytes(&r, self.allocator),
            .kem_ciphertext = try readBytes(&r, self.allocator),
            .vmk_wrapped = try readBytes(&r, self.allocator),
            .created_at = try r.takeInt(i64, .little),
        });
    }

    const n_sas = try r.takeInt(u32, .little);
    for (0..n_sas) |_| {
        try self.service_accounts.append(self.allocator, .{
            .node_id = try readBytes(&r, self.allocator),
            .credentials_wrapped = try readBytes(&r, self.allocator),
            .quota_limit_bytes = try r.takeInt(u64, .little),
            .quota_used_bytes = try r.takeInt(u64, .little),
            .catalog_headroom_bytes = try r.takeInt(u64, .little),
            .catalog_role = @enumFromInt(try r.takeByte()),
            .status = @enumFromInt(try r.takeByte()),
            .last_quota_sync_at = try r.takeInt(i64, .little),
        });
    }

    const n_leases = try r.takeInt(u32, .little);
    for (0..n_leases) |_| {
        try self.leases.append(self.allocator, .{
            .lease_id = try readBytes(&r, self.allocator),
            .device_id = try readBytes(&r, self.allocator),
            .node_id = try readBytes(&r, self.allocator),
            .reserved_bytes = try r.takeInt(u64, .little),
            .purpose = @enumFromInt(try r.takeByte()),
            .expires_at = try r.takeInt(i64, .little),
        });
    }

    const n_inodes = try r.takeInt(u32, .little);
    for (0..n_inodes) |_| {
        const inode_id = try readBytes(&r, self.allocator);
        const parent_id = try readOptBytes(&r, self.allocator);
        const name = try readBytes(&r, self.allocator);
        const kind: InodeKind = @enumFromInt(try r.takeByte());
        const logical_size = try r.takeInt(u64, .little);
        const compression_mode = try readBytes(&r, self.allocator);
        const file_dek_wrapped = try readOptBytes(&r, self.allocator);
        const sha_opt = try readOptBytes(&r, self.allocator);
        defer if (sha_opt) |s| self.allocator.free(s);
        var sha: ?[32]u8 = null;
        if (sha_opt) |s| {
            if (s.len != 32) return error.InvalidSnapshotEncoding;
            sha = s[0..32].*;
        }
        const mime_type = try readOptBytes(&r, self.allocator);
        const mtime = try r.takeInt(i64, .little);

        try self.inodes.append(self.allocator, .{
            .inode_id = inode_id,
            .parent_id = parent_id,
            .name = name,
            .kind = kind,
            .logical_size = logical_size,
            .compression_mode = compression_mode,
            .file_dek_wrapped = file_dek_wrapped,
            .content_sha256 = sha,
            .mime_type = mime_type,
            .mtime = mtime,
        });
    }

    const n_extents = try r.takeInt(u32, .little);
    for (0..n_extents) |_| {
        try self.extents.append(self.allocator, .{
            .inode_id = try readBytes(&r, self.allocator),
            .part_index = try r.takeInt(u32, .little),
            .logical_offset = try r.takeInt(u64, .little),
            .logical_len = try r.takeInt(u64, .little),
            .node_id = try readBytes(&r, self.allocator),
            .remote_object_id = try readBytes(&r, self.allocator),
            .remote_blob_name = try readBytes(&r, self.allocator),
            .physical_size = try r.takeInt(u64, .little),
            .phys_part_offset = try r.takeInt(u64, .little),
            .phys_part_len = try r.takeInt(u64, .little),
        });
    }

    const n_gc = try r.takeInt(u32, .little);
    for (0..n_gc) |_| {
        try self.pending_gc.append(self.allocator, .{
            .gc_id = try readBytes(&r, self.allocator),
            .node_id = try readBytes(&r, self.allocator),
            .remote_object_id = try readBytes(&r, self.allocator),
            .marked_at = try r.takeInt(i64, .little),
        });
    }
}

const SNAPSHOT_MAGIC: [8]u8 = .{ 'G', 'D', 'R', 'V', 'C', 'A', 'T', '1' };

fn writeBytes(w: *std.Io.Writer, bytes: []const u8) !void {
    try w.writeInt(u32, @intCast(bytes.len), .little);
    try w.writeAll(bytes);
}

fn writeOptBytes(w: *std.Io.Writer, opt: ?[]const u8) !void {
    if (opt) |b| {
        try w.writeByte(1);
        try writeBytes(w, b);
    } else {
        try w.writeByte(0);
    }
}

fn readBytes(r: *std.Io.Reader, allocator: std.mem.Allocator) ![]u8 {
    const len = try r.takeInt(u32, .little);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try r.readSliceAll(buf);
    return buf;
}

fn readOptBytes(r: *std.Io.Reader, allocator: std.mem.Allocator) !?[]u8 {
    const present = try r.takeByte();
    if (present == 0) return null;
    if (present != 1) return error.InvalidSnapshotEncoding;
    return try readBytes(r, allocator);
}
