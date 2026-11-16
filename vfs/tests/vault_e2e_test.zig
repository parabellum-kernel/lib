const std = @import("std");
const vfs = @import("vfs");

const InMemoryBlobStore = vfs.InMemoryBlobStore;
const CompositeBlobStore = vfs.CompositeBlobStore;
const InMemoryCatalog = vfs.InMemoryCatalog;
const Provisioner = vfs.Provisioner;
const Vault = vfs.Vault;
const PoolAllocator = vfs.PoolAllocator;

test "Vault full lifecycle over InMemoryBlobStore and CompositeBlobStore" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const kp = try Provisioner.keygenDevice(io);

    var node1_store = InMemoryBlobStore.init(allocator);
    defer node1_store.deinit();
    try node1_store.setNodeQuotaLimit("local:disk1", 10 * 1024 * 1024);

    var node2_store = InMemoryBlobStore.init(allocator);
    defer node2_store.deinit();
    try node2_store.setNodeQuotaLimit("cloud:s3-1", 10 * 1024 * 1024);

    var comp = CompositeBlobStore.init(allocator);
    defer comp.deinit();
    try comp.registerNode("local:disk1", node1_store.port());
    try comp.registerNode("cloud:s3-1", node2_store.port());

    var cat = InMemoryCatalog.init(allocator);
    defer cat.deinit();

    const nodes = [_]Provisioner.NodeConfig{
        .{ .node_id = "local:disk1", .secret_config = "{\"path\":\"/mnt/disk1\"}" },
        .{ .node_id = "cloud:s3-1", .secret_config = "{\"bucket\":\"my-vfs\"}" },
    };

    var vault = try Vault.create(
        allocator,
        io,
        comp.port(),
        cat.port(),
        "vault-hybrid",
        "pc-01",
        kp.public_key,
        &nodes,
        .{},
        1700000000,
    );
    defer vault.deinit();

    // 1. Write & readAt
    const payload = "Backend-agnostic lib-vfs payload!";
    const f_id = try vault.write(null, "hello.txt", payload, .{}, 1700000010);
    defer allocator.free(f_id);

    var out: [payload.len]u8 = undefined;
    try std.testing.expectEqual(payload.len, try vault.readAt(f_id, 0, &out));
    try std.testing.expectEqualStrings(payload, &out);

    // Second read hits RangeCache
    const misses_1 = vault.session.range_cache.misses;
    const hits_1 = vault.session.range_cache.hits;
    var out_cached: [payload.len]u8 = undefined;
    try std.testing.expectEqual(payload.len, try vault.readAt(f_id, 0, &out_cached));
    try std.testing.expectEqual(misses_1, vault.session.range_cache.misses);
    try std.testing.expect(vault.session.range_cache.hits > hits_1);

    // 2. writePacked
    const batch = [_]Vault.BatchFileInput{
        .{ .name = "s1.txt", .plaintext = "small one" },
        .{ .name = "s2.txt", .plaintext = "small two with extra bytes" },
    };
    const packed_ids = try vault.writePacked(&batch, .{ .auto_pack_enabled = true }, 1700000020);
    defer {
        for (packed_ids) |id| allocator.free(id);
        allocator.free(packed_ids);
    }

    var p2_out: [batch[1].plaintext.len]u8 = undefined;
    try std.testing.expectEqual(batch[1].plaintext.len, try vault.readAt(packed_ids[1], 0, &p2_out));
    try std.testing.expectEqualStrings(batch[1].plaintext, &p2_out);

    // 3. mkdir, rename, listDir, delete, runGc
    const dir_id = try vault.mkdir(null, "docs", 1700000030);
    defer allocator.free(dir_id);
    try vault.rename(f_id, dir_id, "renamed.txt", 1700000040);

    const children = try vault.listDir(dir_id);
    defer allocator.free(children);
    try std.testing.expectEqual(@as(usize, 1), children.len);
    try std.testing.expectEqualStrings("renamed.txt", children[0].name);

    try std.testing.expectError(error.DirectoryNotEmpty, vault.delete(dir_id, 1700000050));
    try vault.delete(f_id, 1700000060);
    try vault.delete(dir_id, 1700000070);

    const gc_deleted = try vault.runGc();
    try std.testing.expectEqual(@as(usize, 1), gc_deleted);

    // 4. PinnedAccountPolicy + getQuotas + syncQuotasFromRemote + refresh
    var pinned = PoolAllocator.PinnedAccountPolicy{ .sa_id = "cloud:s3-1" };
    const p_id = try vault.write(null, "pinned.txt", "pinned to s3", .{ .upload_policy = pinned.policy() }, 1700000080);
    defer allocator.free(p_id);

    var q_local = try vault.getQuotas(1700000090);
    defer q_local.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), q_local.nodes.len);
    try std.testing.expect(q_local.used_bytes > 0);

    var q_remote = try vault.syncQuotasFromRemote(1700000100);
    defer q_remote.deinit(allocator);
    try std.testing.expectEqual(@as(i64, 1700000100), q_remote.nodes[0].last_quota_sync_at);

    try std.testing.expectEqual(false, try vault.refresh());

    // 5. Reopen from remote on a fresh catalog
    var cat2 = InMemoryCatalog.init(allocator);
    defer cat2.deinit();
    var vault2 = try Vault.open(
        allocator,
        io,
        comp.port(),
        cat2.port(),
        "vault-hybrid",
        "local:disk1",
        vault.catalog_object_id,
        "pc-01",
        kp.secret_key,
        .{},
    );
    defer vault2.deinit();

    try std.testing.expect(vault2.stat(null, "pinned.txt") != null);
    var reopened_buf: [12]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 12), try vault2.readAt(p_id, 0, &reopened_buf));
    try std.testing.expectEqualStrings("pinned to s3", &reopened_buf);
}

