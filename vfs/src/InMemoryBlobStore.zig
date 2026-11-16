const std = @import("std");
const BlobStorePort = @import("BlobStorePort.zig");

/// Deterministic in-memory `BlobStorePort` backend for unit and E2E tests (`ARCH-037C`).
const InMemoryBlobStore = @This();

const StoredObject = struct {
    node_id: []u8,
    name: []u8,
    data: []u8,
    etag: []u8,
    version: u64,

    fn deinit(self: *StoredObject, allocator: std.mem.Allocator) void {
        allocator.free(self.node_id);
        allocator.free(self.name);
        allocator.free(self.data);
        allocator.free(self.etag);
    }
};

allocator: std.mem.Allocator,
objects: std.StringHashMapUnmanaged(StoredObject) = .empty,
node_limits: std.StringHashMapUnmanaged(u64) = .empty,
default_limit_bytes: u64 = 10 * 1024 * 1024 * 1024,
next_id: u64 = 1,

pub fn init(allocator: std.mem.Allocator) InMemoryBlobStore {
    return .{ .allocator = allocator };
}

pub fn deinit(self: *InMemoryBlobStore) void {
    var it = self.objects.iterator();
    while (it.next()) |e| {
        self.allocator.free(e.key_ptr.*);
        e.value_ptr.deinit(self.allocator);
    }
    self.objects.deinit(self.allocator);

    var lit = self.node_limits.iterator();
    while (lit.next()) |e| {
        self.allocator.free(e.key_ptr.*);
    }
    self.node_limits.deinit(self.allocator);
}

pub fn setNodeQuotaLimit(self: *InMemoryBlobStore, node_id: []const u8, limit_bytes: u64) !void {
    if (self.node_limits.getPtr(node_id)) |ptr| {
        ptr.* = limit_bytes;
        return;
    }
    try self.node_limits.put(self.allocator, try self.allocator.dupe(u8, node_id), limit_bytes);
}

pub fn port(self: *InMemoryBlobStore) BlobStorePort {
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

fn putObjectImpl(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    node_id: []const u8,
    name: []const u8,
    data: []const u8,
) anyerror!BlobStorePort.PutResult {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    const id_num = self.next_id;
    self.next_id += 1;

    const obj_id = try std.fmt.allocPrint(self.allocator, "obj-{d}", .{id_num});
    errdefer self.allocator.free(obj_id);
    const owned_node = try self.allocator.dupe(u8, node_id);
    errdefer self.allocator.free(owned_node);
    const owned_name = try self.allocator.dupe(u8, name);
    errdefer self.allocator.free(owned_name);
    const owned_data = try self.allocator.dupe(u8, data);
    errdefer self.allocator.free(owned_data);
    const etag = try std.fmt.allocPrint(self.allocator, "\"E{d}-1\"", .{id_num});
    errdefer self.allocator.free(etag);

    try self.objects.put(self.allocator, obj_id, .{
        .node_id = owned_node,
        .name = owned_name,
        .data = owned_data,
        .etag = etag,
        .version = 1,
    });

    return .{
        .object_id = try allocator.dupe(u8, obj_id),
        .etag = try allocator.dupe(u8, etag),
    };
}

fn getObjectImpl(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    _: []const u8,
    object_id: []const u8,
) anyerror!BlobStorePort.GetResult {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    const obj = self.objects.get(object_id) orelse return error.ObjectNotFound;
    return .{
        .data = try allocator.dupe(u8, obj.data),
        .etag = try allocator.dupe(u8, obj.etag),
    };
}

fn getRangeImpl(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    _: []const u8,
    object_id: []const u8,
    start: u64,
    end_inclusive: u64,
) anyerror![]u8 {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    const obj = self.objects.get(object_id) orelse return error.ObjectNotFound;
    if (start > end_inclusive or end_inclusive >= obj.data.len) return error.RangeOutOfBounds;
    return allocator.dupe(u8, obj.data[@intCast(start) .. @intCast(end_inclusive + 1)]);
}

fn updateObjectIfMatchImpl(
    ptr: *anyopaque,
    allocator: std.mem.Allocator,
    _: []const u8,
    object_id: []const u8,
    expected_etag: ?[]const u8,
    data: []const u8,
) anyerror![]u8 {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    const obj = self.objects.getPtr(object_id) orelse return error.ObjectNotFound;
    if (expected_etag) |exp| {
        if (!std.mem.eql(u8, exp, obj.etag)) return error.PreconditionFailed;
    }

    const new_data = try self.allocator.dupe(u8, data);
    errdefer self.allocator.free(new_data);
    const new_ver = obj.version + 1;
    const new_etag = try std.fmt.allocPrint(self.allocator, "\"E-{s}-{d}\"", .{ object_id, new_ver });
    errdefer self.allocator.free(new_etag);

    self.allocator.free(obj.data);
    self.allocator.free(obj.etag);
    obj.data = new_data;
    obj.etag = new_etag;
    obj.version = new_ver;

    return allocator.dupe(u8, new_etag);
}

fn deleteObjectImpl(
    ptr: *anyopaque,
    _: std.mem.Allocator,
    _: []const u8,
    object_id: []const u8,
) anyerror!void {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    if (self.objects.fetchRemove(object_id)) |kv| {
        self.allocator.free(kv.key);
        var val = kv.value;
        val.deinit(self.allocator);
        return;
    }
    return error.ObjectNotFound;
}

fn getQuotaImpl(
    ptr: *anyopaque,
    _: std.mem.Allocator,
    node_id: []const u8,
) anyerror!BlobStorePort.QuotaInfo {
    const self: *InMemoryBlobStore = @ptrCast(@alignCast(ptr));
    var used: u64 = 0;
    var it = self.objects.iterator();
    while (it.next()) |e| {
        if (std.mem.eql(u8, e.value_ptr.node_id, node_id)) {
            used +|= e.value_ptr.data.len;
        }
    }
    const limit = self.node_limits.get(node_id) orelse self.default_limit_bytes;
    return .{
        .limit_bytes = limit,
        .used_bytes = used,
    };
}

