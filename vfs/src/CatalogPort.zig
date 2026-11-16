const std = @import("std");

/// Hexagonal catalog persistence port.
/// `lib-gdrive-vfs` never depends directly on `sqlite3`: hosts/apps may back this port
/// with any routed datasource (e.g. `sqlite` via `pipeline.yaml`) or `InMemoryCatalog`.
const CatalogPort = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    getMeta: *const fn (ptr: *anyopaque) VfsMeta,
    setMeta: *const fn (ptr: *anyopaque, meta: VfsMeta) anyerror!void,

    putKeySlot: *const fn (ptr: *anyopaque, slot: VaultKeySlot) anyerror!void,
    getKeySlot: *const fn (ptr: *anyopaque, slot_id: []const u8) ?VaultKeySlot,
    deleteKeySlot: *const fn (ptr: *anyopaque, slot_id: []const u8) bool,

    putStorageNode: *const fn (ptr: *anyopaque, sa: StorageNodeEntry) anyerror!void,
    listStorageNodes: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]StorageNodeEntry,

    putLease: *const fn (ptr: *anyopaque, lease: UploadLease) anyerror!void,
    deleteLease: *const fn (ptr: *anyopaque, lease_id: []const u8) bool,
    listActiveLeases: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, now_unix_s: i64) anyerror![]UploadLease,
    pruneExpiredLeases: *const fn (ptr: *anyopaque, now_unix_s: i64) usize,

    putInode: *const fn (ptr: *anyopaque, inode: Inode) anyerror!void,
    getInode: *const fn (ptr: *anyopaque, inode_id: []const u8) ?Inode,
    findInodeByName: *const fn (ptr: *anyopaque, parent_id: ?[]const u8, name: []const u8) ?Inode,
    listChildren: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, parent_id: ?[]const u8) anyerror![]Inode,
    deleteInode: *const fn (ptr: *anyopaque, inode_id: []const u8) bool,

    putExtent: *const fn (ptr: *anyopaque, extent: InodeExtent) anyerror!void,
    listExtents: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, inode_id: []const u8) anyerror![]InodeExtent,

    markGc: *const fn (ptr: *anyopaque, entry: PendingGcEntry) anyerror!void,
    listPendingGc: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]PendingGcEntry,
    deleteGc: *const fn (ptr: *anyopaque, gc_id: []const u8) bool,

    exportSnapshot: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8,
    importSnapshot: *const fn (ptr: *anyopaque, snapshot_bytes: []const u8) anyerror!void,
};

pub fn getMeta(self: CatalogPort) VfsMeta {
    return self.vtable.getMeta(self.ptr);
}
pub fn setMeta(self: CatalogPort, meta: VfsMeta) !void {
    return self.vtable.setMeta(self.ptr, meta);
}
pub fn putKeySlot(self: CatalogPort, slot: VaultKeySlot) !void {
    return self.vtable.putKeySlot(self.ptr, slot);
}
pub fn getKeySlot(self: CatalogPort, slot_id: []const u8) ?VaultKeySlot {
    return self.vtable.getKeySlot(self.ptr, slot_id);
}
pub fn deleteKeySlot(self: CatalogPort, slot_id: []const u8) bool {
    return self.vtable.deleteKeySlot(self.ptr, slot_id);
}
pub fn putStorageNode(self: CatalogPort, sa: StorageNodeEntry) !void {
    return self.vtable.putStorageNode(self.ptr, sa);
}
pub fn listStorageNodes(self: CatalogPort, allocator: std.mem.Allocator) ![]StorageNodeEntry {
    return self.vtable.listStorageNodes(self.ptr, allocator);
}
pub fn putLease(self: CatalogPort, lease: UploadLease) !void {
    return self.vtable.putLease(self.ptr, lease);
}
pub fn deleteLease(self: CatalogPort, lease_id: []const u8) bool {
    return self.vtable.deleteLease(self.ptr, lease_id);
}
pub fn listActiveLeases(self: CatalogPort, allocator: std.mem.Allocator, now_unix_s: i64) ![]UploadLease {
    return self.vtable.listActiveLeases(self.ptr, allocator, now_unix_s);
}
pub fn pruneExpiredLeases(self: CatalogPort, now_unix_s: i64) usize {
    return self.vtable.pruneExpiredLeases(self.ptr, now_unix_s);
}
pub fn putInode(self: CatalogPort, inode: Inode) !void {
    return self.vtable.putInode(self.ptr, inode);
}
pub fn getInode(self: CatalogPort, inode_id: []const u8) ?Inode {
    return self.vtable.getInode(self.ptr, inode_id);
}
pub fn findInodeByName(self: CatalogPort, parent_id: ?[]const u8, name: []const u8) ?Inode {
    return self.vtable.findInodeByName(self.ptr, parent_id, name);
}
pub fn listChildren(self: CatalogPort, allocator: std.mem.Allocator, parent_id: ?[]const u8) ![]Inode {
    return self.vtable.listChildren(self.ptr, allocator, parent_id);
}
pub fn deleteInode(self: CatalogPort, inode_id: []const u8) bool {
    return self.vtable.deleteInode(self.ptr, inode_id);
}
pub fn putExtent(self: CatalogPort, extent: InodeExtent) !void {
    return self.vtable.putExtent(self.ptr, extent);
}
pub fn listExtents(self: CatalogPort, allocator: std.mem.Allocator, inode_id: []const u8) ![]InodeExtent {
    return self.vtable.listExtents(self.ptr, allocator, inode_id);
}
pub fn markGc(self: CatalogPort, entry: PendingGcEntry) !void {
    return self.vtable.markGc(self.ptr, entry);
}
pub fn listPendingGc(self: CatalogPort, allocator: std.mem.Allocator) ![]PendingGcEntry {
    return self.vtable.listPendingGc(self.ptr, allocator);
}
pub fn deleteGc(self: CatalogPort, gc_id: []const u8) bool {
    return self.vtable.deleteGc(self.ptr, gc_id);
}
pub fn exportSnapshot(self: CatalogPort, allocator: std.mem.Allocator) ![]u8 {
    return self.vtable.exportSnapshot(self.ptr, allocator);
}
pub fn importSnapshot(self: CatalogPort, snapshot_bytes: []const u8) !void {
    return self.vtable.importSnapshot(self.ptr, snapshot_bytes);
}

/// Replays deterministic delta operations onto the catalog (used after `412 Precondition Failed`).
pub fn applyDelta(self: CatalogPort, ops: []const CatalogDeltaOp) !void {
    for (ops) |op| {
        switch (op) {
            .put_lease => |l| try self.putLease(l),
            .delete_lease => |id| _ = self.deleteLease(id),
            .put_inode => |in| try self.putInode(in),
            .delete_inode => |id| _ = self.deleteInode(id),
            .put_extent => |ex| try self.putExtent(ex),
            .mark_gc => |gc| try self.markGc(gc),
            .delete_gc => |id| _ = self.deleteGc(id),
        }
    }
}

/// Reusable conformance test suite that external `CatalogPort` adapters (e.g., routed SQLite)
/// can call in their own unit tests to verify full contract compliance.
pub fn runConformanceSuite(allocator: std.mem.Allocator, port: CatalogPort) !void {
    const t = std.testing;

    // 1. Metadata
    try port.setMeta(.{ .vfs_epoch = 7, .last_writer_device_id = "dev-conformance" });
    try t.expectEqual(@as(u64, 7), port.getMeta().vfs_epoch);
    try t.expectEqualStrings("dev-conformance", port.getMeta().last_writer_device_id);

    // 2. Key slots
    try port.putKeySlot(.{
        .slot_id = "slot-1",
        .label = "laptop",
        .public_key = "pk-bytes",
        .kem_ciphertext = "ct-bytes",
        .vmk_wrapped = "vmk-bytes",
        .created_at = 100,
    });
    const got_slot = port.getKeySlot("slot-1") orelse return error.ConformanceMissingKeySlot;
    try t.expectEqualStrings("laptop", got_slot.label);
    try t.expect(port.deleteKeySlot("slot-1"));
    try t.expect(port.getKeySlot("slot-1") == null);

    // 3. Service accounts (including update without losing credentials_wrapped)
    try port.putStorageNode(.{
        .node_id = "sa-conf@example.com",
        .credentials_wrapped = "wrapped-secret",
        .quota_limit_bytes = 10000,
        .quota_used_bytes = 100,
        .last_quota_sync_at = 100,
    });
    const sas = try port.listStorageNodes(allocator);
    defer allocator.free(sas);
    try t.expectEqual(@as(usize, 1), sas.len);
    var updated_sa = sas[0];
    updated_sa.catalog_role = .primary;
    try port.putStorageNode(updated_sa);
    const sas2 = try port.listStorageNodes(allocator);
    defer allocator.free(sas2);
    try t.expectEqual(CatalogRole.primary, sas2[0].catalog_role);
    try t.expectEqualStrings("wrapped-secret", sas2[0].credentials_wrapped);

    // 4. Inodes + extents (inserted out of order, must return sorted by part_index; delete cascades)
    try port.putInode(.{
        .inode_id = "in-1",
        .parent_id = null,
        .name = "file.bin",
        .kind = .file,
        .logical_size = 2048,
        .mtime = 200,
    });
    try t.expect(port.getInode("in-1") != null);
    try t.expect(port.findInodeByName(null, "file.bin") != null);

    const root_children = try port.listChildren(allocator, null);
    defer allocator.free(root_children);
    try t.expectEqual(@as(usize, 1), root_children.len);
    try t.expectEqualStrings("file.bin", root_children[0].name);

    try port.putExtent(.{
        .inode_id = "in-1",
        .part_index = 1,
        .logical_offset = 1024,
        .logical_len = 1024,
        .node_id = "sa-conf@example.com",
        .remote_object_id = "gd-2",
        .remote_blob_name = "in-1_1.part",
        .physical_size = 1100,
        .phys_part_offset = 64,
        .phys_part_len = 1036,
    });
    try port.putExtent(.{
        .inode_id = "in-1",
        .part_index = 0,
        .logical_offset = 0,
        .logical_len = 1024,
        .node_id = "sa-conf@example.com",
        .remote_object_id = "gd-1",
        .remote_blob_name = "in-1_0.part",
        .physical_size = 1100,
    });
    const exts = try port.listExtents(allocator, "in-1");
    defer allocator.free(exts);
    try t.expectEqual(@as(usize, 2), exts.len);
    try t.expectEqual(@as(u32, 0), exts[0].part_index);
    try t.expectEqual(@as(u32, 1), exts[1].part_index);
    try t.expectEqual(@as(u64, 64), exts[1].phys_part_offset);

    // 5. Leases & GC
    try port.putLease(.{ .lease_id = "l-exp", .device_id = "d", .node_id = "sa-conf@example.com", .reserved_bytes = 50, .expires_at = 10 });
    try port.putLease(.{ .lease_id = "l-ok", .device_id = "d", .node_id = "sa-conf@example.com", .reserved_bytes = 50, .expires_at = 500 });
    const active = try port.listActiveLeases(allocator, 100);
    defer allocator.free(active);
    try t.expectEqual(@as(usize, 1), active.len);
    try t.expectEqualStrings("l-ok", active[0].lease_id);
    try t.expectEqual(@as(usize, 1), port.pruneExpiredLeases(100));

    try port.markGc(.{ .gc_id = "gc-1", .node_id = "sa-conf@example.com", .remote_object_id = "gd-old", .marked_at = 100 });
    const gcs = try port.listPendingGc(allocator);
    defer allocator.free(gcs);
    try t.expectEqual(@as(usize, 1), gcs.len);
    try t.expect(port.deleteGc("gc-1"));
    const gcs_after = try port.listPendingGc(allocator);
    defer allocator.free(gcs_after);
    try t.expectEqual(@as(usize, 0), gcs_after.len);

    // 6. Snapshot round-trip + cascade delete
    const snap = try port.exportSnapshot(allocator);
    defer allocator.free(snap);
    try t.expect(port.deleteInode("in-1"));
    const exts_after = try port.listExtents(allocator, "in-1");
    defer allocator.free(exts_after);
    try t.expectEqual(@as(usize, 0), exts_after.len);

    try port.importSnapshot(snap);
    try t.expect(port.findInodeByName(null, "file.bin") != null);
}

pub const VfsMeta = struct {
    schema_version: u32 = 1,
    vfs_epoch: u64 = 1,
    last_writer_device_id: []const u8 = "",
    last_writer_sdk_semver: []const u8 = "0.1.0",
    last_observed_api_id: []const u8 = "drive:v3",
    last_observed_api_revision: []const u8 = "20261029",
};

pub const VaultKeySlot = struct {
    slot_id: []const u8,
    label: []const u8,
    kem_alg: []const u8 = "MLKEM768-X25519",
    aead_alg: []const u8 = "XChaCha20-Poly1305",
    public_key: []const u8,
    kem_ciphertext: []const u8,
    vmk_wrapped: []const u8,
    created_at: i64,
};

pub const CatalogRole = enum(u8) { none = 0, primary = 1, replica = 2 };
pub const AccountStatus = enum(u8) { active = 0, full = 1, disabled = 2 };

pub const StorageNodeEntry = struct {
    node_id: []const u8,
    credentials_wrapped: []const u8,
    quota_limit_bytes: u64,
    quota_used_bytes: u64,
    catalog_headroom_bytes: u64 = 0,
    catalog_role: CatalogRole = .none,
    status: AccountStatus = .active,
    last_quota_sync_at: i64,
};

pub const LeasePurpose = enum(u8) { part_upload = 0, catalog_sync = 1 };

pub const UploadLease = struct {
    lease_id: []const u8,
    device_id: []const u8,
    node_id: []const u8,
    reserved_bytes: u64,
    purpose: LeasePurpose = .part_upload,
    expires_at: i64,
};

pub const InodeKind = enum(u8) { dir = 0, file = 1 };

pub const Inode = struct {
    inode_id: []const u8,
    parent_id: ?[]const u8 = null,
    name: []const u8,
    kind: InodeKind,
    logical_size: u64 = 0,
    compression_mode: []const u8 = "auto",
    file_dek_wrapped: ?[]const u8 = null,
    content_sha256: ?[32]u8 = null,
    mime_type: ?[]const u8 = null,
    mtime: i64,
};

pub const InodeExtent = struct {
    inode_id: []const u8,
    part_index: u32,
    logical_offset: u64,
    logical_len: u64,
    node_id: []const u8,
    remote_object_id: []const u8,
    remote_blob_name: []const u8,
    physical_size: u64,
    phys_part_offset: u64 = 0,
    phys_part_len: u64 = 0,
};

pub const PendingGcEntry = struct {
    gc_id: []const u8,
    node_id: []const u8,
    remote_object_id: []const u8,
    marked_at: i64,
};

pub const CatalogDeltaOp = union(enum) {
    put_lease: UploadLease,
    delete_lease: []const u8,
    put_inode: Inode,
    delete_inode: []const u8,
    put_extent: InodeExtent,
    mark_gc: PendingGcEntry,
    delete_gc: []const u8,
};
