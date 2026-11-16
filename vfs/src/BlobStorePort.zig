const std = @import("std");

/// Hexagonal physical blob storage port (`ARCH-037B`).
/// Backends (`gdrive-vfs`, `local-vfs`, `ssh-vfs`, `s3-vfs`, `mega-vfs`, `InMemoryBlobStore`)
/// implement this `VTable` so the encrypted VFS core remains completely storage-agnostic.
const BlobStorePort = @This();

ptr: *anyopaque,
vtable: *const VTable,

pub const PutResult = struct {
    object_id: []u8,
    etag: ?[]u8 = null,

    pub fn deinit(self: *PutResult, allocator: std.mem.Allocator) void {
        allocator.free(self.object_id);
        if (self.etag) |e| allocator.free(e);
    }
};

pub const GetResult = struct {
    data: []u8,
    etag: ?[]u8 = null,

    pub fn deinit(self: *GetResult, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        if (self.etag) |e| allocator.free(e);
    }
};

pub const QuotaInfo = struct {
    limit_bytes: u64,
    used_bytes: u64,
};

pub const VTable = struct {
    putObject: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        name: []const u8,
        data: []const u8,
    ) anyerror!PutResult,

    getObject: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        object_id: []const u8,
    ) anyerror!GetResult,

    getRange: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        object_id: []const u8,
        start: u64,
        end_inclusive: u64,
    ) anyerror![]u8,

    updateObjectIfMatch: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        object_id: []const u8,
        expected_etag: ?[]const u8,
        data: []const u8,
    ) anyerror![]u8,

    deleteObject: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
        object_id: []const u8,
    ) anyerror!void,

    getQuota: *const fn (
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        node_id: []const u8,
    ) anyerror!QuotaInfo,
};

pub fn putObject(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    name: []const u8,
    data: []const u8,
) !PutResult {
    return self.vtable.putObject(self.ptr, allocator, node_id, name, data);
}

pub fn getObject(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    object_id: []const u8,
) !GetResult {
    return self.vtable.getObject(self.ptr, allocator, node_id, object_id);
}

pub fn getRange(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    object_id: []const u8,
    start: u64,
    end_inclusive: u64,
) ![]u8 {
    return self.vtable.getRange(self.ptr, allocator, node_id, object_id, start, end_inclusive);
}

pub fn updateObjectIfMatch(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    object_id: []const u8,
    expected_etag: ?[]const u8,
    data: []const u8,
) ![]u8 {
    return self.vtable.updateObjectIfMatch(self.ptr, allocator, node_id, object_id, expected_etag, data);
}

pub fn deleteObject(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    object_id: []const u8,
) !void {
    return self.vtable.deleteObject(self.ptr, allocator, node_id, object_id);
}

pub fn getQuota(
    self: BlobStorePort,
    allocator: std.mem.Allocator,
    node_id: []const u8,
) !QuotaInfo {
    return self.vtable.getQuota(self.ptr, allocator, node_id);
}

/// Reusable conformance test suite that all `lib/<backend>-vfs` adapters
/// (`gdrive-vfs`, `local-vfs`, `ssh-vfs`, `s3-vfs`, `mega-vfs`) must pass.
pub fn runConformanceSuite(allocator: std.mem.Allocator, store: BlobStorePort, node_id: []const u8) !void {
    const t = std.testing;

    // 1. Put + Get round-trip
    var put1 = try store.putObject(allocator, node_id, "conf_blob.bin", "0123456789abcdef");
    defer put1.deinit(allocator);
    try t.expect(put1.object_id.len > 0);
    try t.expect(put1.etag != null);

    var got1 = try store.getObject(allocator, node_id, put1.object_id);
    defer got1.deinit(allocator);
    try t.expectEqualStrings("0123456789abcdef", got1.data);

    // 2. Partial getRange (first byte, middle slice, last byte)
    const r_first = try store.getRange(allocator, node_id, put1.object_id, 0, 0);
    defer allocator.free(r_first);
    try t.expectEqualStrings("0", r_first);

    const r_mid = try store.getRange(allocator, node_id, put1.object_id, 4, 9);
    defer allocator.free(r_mid);
    try t.expectEqualStrings("456789", r_mid);

    const r_last = try store.getRange(allocator, node_id, put1.object_id, 15, 15);
    defer allocator.free(r_last);
    try t.expectEqualStrings("f", r_last);

    // 3. Optimistic CAS (updateObjectIfMatch)
    const new_etag = try store.updateObjectIfMatch(allocator, node_id, put1.object_id, put1.etag, "updated_payload!");
    defer allocator.free(new_etag);

    try t.expectError(
        error.PreconditionFailed,
        store.updateObjectIfMatch(allocator, node_id, put1.object_id, put1.etag, "stale_write"),
    );

    var got2 = try store.getObject(allocator, node_id, put1.object_id);
    defer got2.deinit(allocator);
    try t.expectEqualStrings("updated_payload!", got2.data);

    // 4. Quota reflects stored bytes
    const q = try store.getQuota(allocator, node_id);
    try t.expect(q.limit_bytes >= q.used_bytes);
    try t.expect(q.used_bytes >= "updated_payload!".len);

    // 5. Delete removes object
    try store.deleteObject(allocator, node_id, put1.object_id);
    try t.expectError(error.ObjectNotFound, store.getObject(allocator, node_id, put1.object_id));
}

