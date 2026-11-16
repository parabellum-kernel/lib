const std = @import("std");
const BlobStorePort = @import("BlobStorePort.zig");

/// Routes `BlobStorePort` calls by `node_id` across heterogeneous backends
/// (e.g. `local:nas` -> `LocalFsBlobStore`, `gdrive:sa1` -> `GDriveBlobStore`).
const CompositeBlobStore = @This();

allocator: std.mem.Allocator,
routes: std.StringHashMapUnmanaged(BlobStorePort) = .empty,

pub fn init(allocator: std.mem.Allocator) CompositeBlobStore {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *CompositeBlobStore) void {
    var it = self.routes.iterator();
    while (it.next()) |e| self.allocator.free(e.key_ptr.*);
    self.routes.deinit(self.allocator);
}

pub fn registerNode(self: *CompositeBlobStore, node_id: []const u8, backend: BlobStorePort) !void {
    if (self.routes.getPtr(node_id)) |p| {
        p.* = backend;
        return;
    }
    try self.routes.put(self.allocator, try self.allocator.dupe(u8, node_id), backend);
}

pub fn port(self: *CompositeBlobStore) BlobStorePort {
    return .{ .ptr = self, .vtable = &vtable };
}

const vtable = BlobStorePort.VTable{
    .putObject = putObjectImpl,
    .getObject = getObjectImpl,
    .getRange = getRangeImpl,
    .updateObjectIfMatch = updateObjectIfMatchImpl,
    .deleteObject = deleteObjectImpl,
    .getQuota = getQuotaImpl,
};

fn resolve(self: *const CompositeBlobStore, node_id: []const u8) !BlobStorePort {
    return self.routes.get(node_id) orelse error.UnknownStorageNode;
}

fn putObjectImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8, name: []const u8, data: []const u8) anyerror!BlobStorePort.PutResult {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).putObject(allocator, node_id, name, data);
}

fn getObjectImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8, object_id: []const u8) anyerror!BlobStorePort.GetResult {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).getObject(allocator, node_id, object_id);
}

fn getRangeImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8, object_id: []const u8, start: u64, end_inclusive: u64) anyerror![]u8 {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).getRange(allocator, node_id, object_id, start, end_inclusive);
}

fn updateObjectIfMatchImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8, object_id: []const u8, expected_etag: ?[]const u8, data: []const u8) anyerror![]u8 {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).updateObjectIfMatch(allocator, node_id, object_id, expected_etag, data);
}

fn deleteObjectImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8, object_id: []const u8) anyerror!void {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).deleteObject(allocator, node_id, object_id);
}

fn getQuotaImpl(ptr: *anyopaque, allocator: std.mem.Allocator, node_id: []const u8) anyerror!BlobStorePort.QuotaInfo {
    const self: *CompositeBlobStore = @ptrCast(@alignCast(ptr));
    return (try self.resolve(node_id)).getQuota(allocator, node_id);
}

