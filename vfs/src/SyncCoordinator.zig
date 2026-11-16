const std = @import("std");
const Crypto = @import("Crypto.zig");
const Compressor = @import("Compressor.zig");
const CatalogPort = @import("CatalogPort.zig");
const BlobStorePort = @import("BlobStorePort.zig");

/// Optimistic Compare-And-Swap (`updateObjectIfMatch`) catalog synchronization over `BlobStorePort`.
const SyncCoordinator = @This();

pub const ENVELOPE_MAGIC = [8]u8{ 'V', 'F', 'S', 'E', 'N', 'V', '0', '1' };

pub const CommitResult = struct {
    new_etag: []u8,
    new_epoch: u64,
    attempts: usize,

    pub fn deinit(self: *CommitResult, allocator: std.mem.Allocator) void {
        allocator.free(self.new_etag);
    }
};

/// Exports, compresses, and seals the current `catalog` snapshot using `vmk` and `vault_id` AAD.
pub fn sealCatalogSnapshot(
    allocator: std.mem.Allocator,
    io: std.Io,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
) ![]u8 {
    const raw = try catalog.exportSnapshot(allocator);
    defer allocator.free(raw);
    const deflated = try Compressor.compressDeflate(allocator, raw);
    defer allocator.free(deflated);
    const sealed = try Crypto.encryptBlobWithNonce(allocator, io, vmk, deflated, vault_id);

    const meta = catalog.getMeta();
    if (meta.last_writer_device_id.len > 0) {
        if (catalog.getKeySlot(meta.last_writer_device_id)) |slot| {
            if (slot.kem_ciphertext.len == Crypto.HybridKem.EncapsulatedSecret.ciphertext_length and
                slot.vmk_wrapped.len == Crypto.WRAPPED_VMK_LEN)
            {
                defer allocator.free(sealed);
                return buildBootstrapEnvelope(
                    allocator,
                    meta.last_writer_device_id,
                    slot.kem_ciphertext[0..Crypto.HybridKem.EncapsulatedSecret.ciphertext_length].*,
                    slot.vmk_wrapped[0..Crypto.WRAPPED_VMK_LEN].*,
                    sealed,
                );
            }
        }
    }
    return sealed;
}

pub fn buildBootstrapEnvelope(
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

pub fn parseBootstrapEnvelope(data: []const u8, device_id: []const u8) !struct {
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

/// Decrypts, decompresses, and imports a remote catalog snapshot into `catalog`.
pub fn openCatalogSnapshot(
    allocator: std.mem.Allocator,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    sealed_blob: []const u8,
) !void {
    var payload = sealed_blob;
    if (payload.len >= ENVELOPE_MAGIC.len and std.mem.eql(u8, payload[0..ENVELOPE_MAGIC.len], &ENVELOPE_MAGIC)) {
        var pos: usize = ENVELOPE_MAGIC.len;
        if (payload.len < pos + 2) return error.InvalidEnvelope;
        const id_len = std.mem.readInt(u16, payload[pos..][0..2], .little);
        pos += 2 + id_len + Crypto.HybridKem.EncapsulatedSecret.ciphertext_length + Crypto.WRAPPED_VMK_LEN;
        if (payload.len < pos) return error.InvalidEnvelope;
        payload = payload[pos..];
    }
    const deflated = try Crypto.decryptBlobWithNonce(allocator, vmk, payload, vault_id);
    defer allocator.free(deflated);
    const raw = try Compressor.decompressDeflate(allocator, deflated, 128 * 1024 * 1024);
    defer allocator.free(raw);
    try catalog.importSnapshot(raw);
}

/// Applies `delta_ops` and commits the sealed catalog snapshot to `store` with optimistic CAS retry.
/// On `error.PreconditionFailed`, pulls the latest remote snapshot, replays `delta_ops`, and retries.
pub fn commitDeltaWithRetry(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: BlobStorePort,
    catalog_node_id: []const u8,
    catalog_object_id: []const u8,
    initial_etag: ?[]const u8,
    catalog: CatalogPort,
    vmk: [Crypto.KEY_LEN]u8,
    vault_id: []const u8,
    delta_ops: []const CatalogPort.CatalogDeltaOp,
    max_retries: usize,
) !CommitResult {
    var current_etag: ?[]u8 = if (initial_etag) |e| try allocator.dupe(u8, e) else null;
    errdefer if (current_etag) |e| allocator.free(e);

    var attempt: usize = 0;
    while (attempt <= max_retries) : (attempt += 1) {
        try catalog.applyDelta(delta_ops);

        var meta = catalog.getMeta();
        meta.vfs_epoch += 1;
        try catalog.setMeta(meta);

        const sealed = try sealCatalogSnapshot(allocator, io, catalog, vmk, vault_id);
        defer allocator.free(sealed);

        const next_etag = store.updateObjectIfMatch(
            allocator,
            catalog_node_id,
            catalog_object_id,
            current_etag,
            sealed,
        ) catch |err| switch (err) {
            error.PreconditionFailed => {
                if (attempt == max_retries) return error.MaxCasRetriesExceeded;

                var latest = try store.getObject(allocator, catalog_node_id, catalog_object_id);
                defer latest.deinit(allocator);

                try openCatalogSnapshot(allocator, catalog, vmk, vault_id, latest.data);

                if (current_etag) |e| allocator.free(e);
                current_etag = latest.etag;
                latest.etag = null;
                continue;
            },
            else => return err,
        };

        if (current_etag) |e| allocator.free(e);
        return .{
            .new_etag = next_etag,
            .new_epoch = meta.vfs_epoch,
            .attempts = attempt + 1,
        };
    }
    return error.MaxCasRetriesExceeded;
}
