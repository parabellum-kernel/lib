const std = @import("std");
const Crypto = @import("Crypto.zig");
const CatalogPort = @import("CatalogPort.zig");
const BlobStorePort = @import("BlobStorePort.zig");
const PoolAllocator = @import("PoolAllocator.zig");
const SyncCoordinator = @import("SyncCoordinator.zig");

/// Backend-agnostic vault provisioning, hybrid KEM device key slots, and remote unlock (`ARCH-037B`).
const Provisioner = @This();

pub const ENVELOPE_MAGIC = [8]u8{ 'V', 'F', 'S', 'E', 'N', 'V', '0', '1' };

pub const NodeConfig = struct {
    node_id: []const u8,
    /// Optional opaque backend configuration/credential bytes wrapped with `VMK`.
    secret_config: []const u8 = "",
};

pub const InitResult = struct {
    vmk: [Crypto.KEY_LEN]u8,
    catalog_object_id: []u8,
    etag: ?[]u8,
    primary_node_id: []u8,

    pub fn deinit(self: *InitResult, allocator: std.mem.Allocator) void {
        allocator.free(self.catalog_object_id);
        if (self.etag) |e| allocator.free(e);
        allocator.free(self.primary_node_id);
    }
};

pub const UnlockResult = struct {
    vmk: [Crypto.KEY_LEN]u8,
    catalog_object_id: []u8,
    etag: ?[]u8,

    pub fn deinit(self: *UnlockResult, allocator: std.mem.Allocator) void {
        allocator.free(self.catalog_object_id);
        if (self.etag) |e| allocator.free(e);
    }
};

/// Generates a fresh post-quantum hybrid device keypair (`MLKEM768-X25519`).
pub fn keygenDevice(io: std.Io) !Crypto.HybridKem.KeyPair {
    return Crypto.HybridKem.KeyPair.generate(io);
}

/// Wraps an opaque per-node configuration/credential payload under `vmk` with `node_id` AAD.
pub fn wrapNodeSecret(
    allocator: std.mem.Allocator,
    io: std.Io,
    vmk: [Crypto.KEY_LEN]u8,
    node_id: []const u8,
    secret_config: []const u8,
) ![]u8 {
    return Crypto.encryptBlobWithNonce(allocator, io, vmk, secret_config, node_id);
}

/// Unwraps a per-node configuration/credential payload previously sealed with `wrapNodeSecret`.
pub fn unwrapNodeSecret(
    allocator: std.mem.Allocator,
    vmk: [Crypto.KEY_LEN]u8,
    node_id: []const u8,
    wrapped: []const u8,
) ![]u8 {
    return Crypto.decryptBlobWithNonce(allocator, vmk, wrapped, node_id);
}

/// Provisions a new encrypted vault over `store` and `catalog`:
/// 1. Generates `VMK` and wraps it for `admin_device_pk`.
/// 2. Queries `store.getQuota` for each node in `nodes` and registers `StorageNodeEntry` records.
/// 3. Seals and uploads the initial catalog object to the primary node.
pub fn initVault(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: BlobStorePort,
    catalog: CatalogPort,
    vault_id: []const u8,
    admin_device_id: []const u8,
    admin_device_pk: Crypto.HybridKem.PublicKey,
    nodes: []const NodeConfig,
    now_unix_s: i64,
) !InitResult {
    if (nodes.len == 0) return error.NoStorageNodes;

    var vmk: [Crypto.KEY_LEN]u8 = undefined;
    io.random(&vmk);

    const wrapped = try Crypto.wrapVmkForDevice(io, vmk, admin_device_pk, admin_device_id);
    try catalog.putKeySlot(.{
        .slot_id = admin_device_id,
        .label = admin_device_id,
        .public_key = &admin_device_pk.toBytes(),
        .kem_ciphertext = &wrapped.kem_ciphertext,
        .vmk_wrapped = &wrapped.vmk_wrapped,
        .created_at = now_unix_s,
    });

    const quotas = try allocator.alloc(PoolAllocator.ServiceAccountQuota, nodes.len);
    defer allocator.free(quotas);

    for (nodes, 0..) |node, i| {
        const q = try store.getQuota(allocator, node.node_id);
        const wrapped_secret = try wrapNodeSecret(allocator, io, vmk, node.node_id, node.secret_config);
        defer allocator.free(wrapped_secret);

        try catalog.putStorageNode(.{
            .node_id = node.node_id,
            .credentials_wrapped = wrapped_secret,
            .quota_limit_bytes = q.limit_bytes,
            .quota_used_bytes = q.used_bytes,
            .catalog_role = .none,
            .last_quota_sync_at = now_unix_s,
        });

        quotas[i] = .{
            .sa_index = i,
            .sa_id = node.node_id,
            .total_bytes = q.limit_bytes,
            .used_bytes = q.used_bytes,
        };
    }

    const primary_idx = PoolAllocator.selectMostAvailableAccount(quotas, 0) orelse 0;
    const primary_node_id = nodes[primary_idx].node_id;

    // Mark primary node in catalog before sealing.
    const stored_nodes = try catalog.listStorageNodes(allocator);
    defer allocator.free(stored_nodes);
    for (stored_nodes) |sn| {
        if (std.mem.eql(u8, sn.node_id, primary_node_id)) {
            var upd = sn;
            upd.catalog_role = .primary;
            try catalog.putStorageNode(upd);
            break;
        }
    }

    var meta = catalog.getMeta();
    meta.last_writer_device_id = admin_device_id;
    try catalog.setMeta(meta);

    const sealed = try SyncCoordinator.sealCatalogSnapshot(allocator, io, catalog, vmk, vault_id);
    defer allocator.free(sealed);

    const cat_name = try std.fmt.allocPrint(allocator, "{s}.vfscat", .{vault_id});
    defer allocator.free(cat_name);

    var uploaded = try store.putObject(allocator, primary_node_id, cat_name, sealed);
    errdefer uploaded.deinit(allocator);

    const owned_primary = try allocator.dupe(u8, primary_node_id);
    errdefer allocator.free(owned_primary);

    const obj_id = uploaded.object_id;
    const etag = uploaded.etag;
    uploaded.object_id = &.{};
    uploaded.etag = null;

    return .{
        .vmk = vmk,
        .catalog_object_id = obj_id,
        .etag = etag,
        .primary_node_id = owned_primary,
    };
}

/// Unlocks an existing vault from `store` using `device_sk` and hydrates `catalog`.
pub fn unlockVaultFromRemote(
    allocator: std.mem.Allocator,
    store: BlobStorePort,
    catalog: CatalogPort,
    vault_id: []const u8,
    catalog_node_id: []const u8,
    catalog_object_id: []const u8,
    device_id: []const u8,
    device_sk: Crypto.HybridKem.SecretKey,
) !UnlockResult {
    var dl = try store.getObject(allocator, catalog_node_id, catalog_object_id);
    errdefer dl.deinit(allocator);

    var vmk: [Crypto.KEY_LEN]u8 = undefined;
    var sealed_payload: []const u8 = dl.data;

    if (dl.data.len >= SyncCoordinator.ENVELOPE_MAGIC.len and
        std.mem.eql(u8, dl.data[0..SyncCoordinator.ENVELOPE_MAGIC.len], &SyncCoordinator.ENVELOPE_MAGIC))
    {
        const parsed = try SyncCoordinator.parseBootstrapEnvelope(dl.data, device_id);
        vmk = try Crypto.unwrapVmkForDevice(device_sk, .{
            .kem_ciphertext = parsed.kem_ciphertext,
            .vmk_wrapped = parsed.vmk_wrapped,
        }, device_id);
        sealed_payload = parsed.sealed_snapshot;
    } else {
        const slot = catalog.getKeySlot(device_id) orelse return error.DeviceKeySlotNotFound;
        if (slot.kem_ciphertext.len != Crypto.HybridKem.EncapsulatedSecret.ciphertext_length or
            slot.vmk_wrapped.len != Crypto.WRAPPED_VMK_LEN)
        {
            return error.InvalidKeySlot;
        }
        vmk = try Crypto.unwrapVmkForDevice(
            device_sk,
            .{
                .kem_ciphertext = slot.kem_ciphertext[0..Crypto.HybridKem.EncapsulatedSecret.ciphertext_length].*,
                .vmk_wrapped = slot.vmk_wrapped[0..Crypto.WRAPPED_VMK_LEN].*,
            },
            device_id,
        );
    }

    try SyncCoordinator.openCatalogSnapshot(allocator, catalog, vmk, vault_id, sealed_payload);

    const owned_obj_id = try allocator.dupe(u8, catalog_object_id);
    const etag = dl.etag;
    dl.etag = null;
    dl.deinit(allocator);

    return .{
        .vmk = vmk,
        .catalog_object_id = owned_obj_id,
        .etag = etag,
    };
}

fn buildBootstrapEnvelope(
    allocator: std.mem.Allocator,
    device_id: []const u8,
    kem_ct: [Crypto.HybridKem.EncapsulatedSecret.ciphertext_length]u8,
    vmk_wrapped: [Crypto.WRAPPED_VMK_LEN]u8,
    sealed_snapshot: []const u8,
) ![]u8 {
    const total = ENVELOPE_MAGIC.len + 2 + device_id.len + kem_ct.len + vmk_wrapped.len + sealed_snapshot.len;
    const buf = try allocator.alloc(u8, total);
    var pos: usize = 0;

    @memcpy(buf[pos..][0..ENVELOPE_MAGIC.len], &ENVELOPE_MAGIC);
    pos += ENVELOPE_MAGIC.len;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(device_id.len), .little);
    pos += 2;
    @memcpy(buf[pos..][0..device_id.len], device_id);
    pos += device_id.len;
    @memcpy(buf[pos..][0..kem_ct.len], &kem_ct);
    pos += kem_ct.len;
    @memcpy(buf[pos..][0..vmk_wrapped.len], &vmk_wrapped);
    pos += vmk_wrapped.len;
    @memcpy(buf[pos..][0..sealed_snapshot.len], sealed_snapshot);

    return buf;
}

fn parseBootstrapEnvelope(data: []const u8, device_id: []const u8) !struct {
    kem_ciphertext: [Crypto.HybridKem.EncapsulatedSecret.ciphertext_length]u8,
    vmk_wrapped: [Crypto.WRAPPED_VMK_LEN]u8,
    sealed_snapshot: []const u8,
} {
    var pos: usize = ENVELOPE_MAGIC.len;
    if (data.len < pos + 2) return error.InvalidEnvelope;
    const id_len = std.mem.readInt(u16, data[pos..][0..2], .little);
    pos += 2;
    if (data.len < pos + id_len + Crypto.HybridKem.EncapsulatedSecret.ciphertext_length + Crypto.WRAPPED_VMK_LEN) {
        return error.InvalidEnvelope;
    }
    const slot_id = data[pos..][0..id_len];
    pos += id_len;
    if (!std.mem.eql(u8, slot_id, device_id)) return error.DeviceKeySlotNotFound;

    const kem_ct = data[pos..][0..Crypto.HybridKem.EncapsulatedSecret.ciphertext_length].*;
    pos += Crypto.HybridKem.EncapsulatedSecret.ciphertext_length;
    const vmk_w = data[pos..][0..Crypto.WRAPPED_VMK_LEN].*;
    pos += Crypto.WRAPPED_VMK_LEN;

    return .{
        .kem_ciphertext = kem_ct,
        .vmk_wrapped = vmk_w,
        .sealed_snapshot = data[pos..],
    };
}
