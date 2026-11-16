const std = @import("std");
const vfs = @import("vfs");
const BlobStorePort = vfs.BlobStorePort;
const InMemoryBlobStore = vfs.InMemoryBlobStore;
const CompositeBlobStore = vfs.CompositeBlobStore;

test "InMemoryBlobStore passes BlobStorePort conformance suite" {
    var store = InMemoryBlobStore.init(std.testing.allocator);
    defer store.deinit();

    try BlobStorePort.runConformanceSuite(std.testing.allocator, store.port(), "node-1");
}

test "CompositeBlobStore routes operations by node_id across heterogeneous backends" {
    const allocator = std.testing.allocator;
    var store_a = InMemoryBlobStore.init(allocator);
    defer store_a.deinit();
    var store_b = InMemoryBlobStore.init(allocator);
    defer store_b.deinit();

    var comp = CompositeBlobStore.init(allocator);
    defer comp.deinit();
    try comp.registerNode("local:nas", store_a.port());
    try comp.registerNode("cloud:s3", store_b.port());

    var p1 = try comp.port().putObject(allocator, "local:nas", "a.part", "alpha");
    defer p1.deinit(allocator);
    var p2 = try comp.port().putObject(allocator, "cloud:s3", "b.part", "beta");
    defer p2.deinit(allocator);

    var g1 = try store_a.port().getObject(allocator, "local:nas", p1.object_id);
    defer g1.deinit(allocator);
    try std.testing.expectEqualStrings("alpha", g1.data);

    var g2 = try store_b.port().getObject(allocator, "cloud:s3", p2.object_id);
    defer g2.deinit(allocator);
    try std.testing.expectEqualStrings("beta", g2.data);

    try std.testing.expectError(error.UnknownStorageNode, comp.port().getQuota(allocator, "missing:node"));
}

