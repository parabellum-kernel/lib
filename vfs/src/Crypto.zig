const std = @import("std");

pub const PAGE_SIZE_BYTES: usize = 256 * 1024;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const WRAPPED_VMK_LEN: usize = KEY_LEN + TAG_LEN;
pub const WRAPPED_KEY_WITH_NONCE_LEN: usize = XCHACHA_NONCE_LEN + KEY_LEN + TAG_LEN;

pub const HybridKem = std.crypto.kem.hybrid.MlKem768X25519;
pub const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
pub const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const KeyHierarchyTier = enum {
    device_kem_mlkem768_x25519,
    volume_master_key,
    file_data_encryption_key,
};

pub const WrappedVmkSlot = struct {
    kem_ciphertext: [HybridKem.EncapsulatedSecret.ciphertext_length]u8,
    vmk_wrapped: [WRAPPED_VMK_LEN]u8,
};

/// Encapsulates a fresh shared secret for `device_pk` and wraps `vmk` with XChaCha20-Poly1305.
/// A zero nonce is safe because each KEM encapsulation yields a fresh ephemeral shared secret.
pub fn wrapVmkForDevice(
    io: std.Io,
    vmk: [KEY_LEN]u8,
    device_pk: HybridKem.PublicKey,
    slot_id_aad: []const u8,
) !WrappedVmkSlot {
    const enc = try device_pk.encaps(io);
    const zero_nonce: [XCHACHA_NONCE_LEN]u8 = @splat(0);

    var wrapped: [WRAPPED_VMK_LEN]u8 = undefined;
    var tag: [TAG_LEN]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        wrapped[0..KEY_LEN],
        &tag,
        &vmk,
        slot_id_aad,
        zero_nonce,
        enc.shared_secret,
    );
    @memcpy(wrapped[KEY_LEN..], &tag);

    return .{
        .kem_ciphertext = enc.ciphertext,
        .vmk_wrapped = wrapped,
    };
}

/// Decapsulates the slot shared secret using `device_sk` and unwraps the VMK.
pub fn unwrapVmkForDevice(
    device_sk: HybridKem.SecretKey,
    slot: WrappedVmkSlot,
    slot_id_aad: []const u8,
) ![KEY_LEN]u8 {
    const kek = try device_sk.decaps(&slot.kem_ciphertext);
    const zero_nonce: [XCHACHA_NONCE_LEN]u8 = @splat(0);

    var vmk: [KEY_LEN]u8 = undefined;
    const tag = slot.vmk_wrapped[KEY_LEN..][0..TAG_LEN].*;
    try XChaCha20Poly1305.decrypt(
        &vmk,
        slot.vmk_wrapped[0..KEY_LEN],
        tag,
        slot_id_aad,
        zero_nonce,
        kek,
    );
    return vmk;
}

/// Wraps a 32-byte key (e.g., File_DEK) using a reusable 32-byte KEK (e.g., VMK) and random 24-byte nonce.
pub fn wrapKeyWithNonce(
    io: std.Io,
    kek: [KEY_LEN]u8,
    key_to_wrap: [KEY_LEN]u8,
    aad: []const u8,
) [WRAPPED_KEY_WITH_NONCE_LEN]u8 {
    var out: [WRAPPED_KEY_WITH_NONCE_LEN]u8 = undefined;
    var nonce: [XCHACHA_NONCE_LEN]u8 = undefined;
    io.random(&nonce);
    @memcpy(out[0..XCHACHA_NONCE_LEN], &nonce);

    var tag: [TAG_LEN]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        out[XCHACHA_NONCE_LEN..][0..KEY_LEN],
        &tag,
        &key_to_wrap,
        aad,
        nonce,
        kek,
    );
    @memcpy(out[XCHACHA_NONCE_LEN + KEY_LEN ..][0..TAG_LEN], &tag);
    return out;
}

/// Unwraps a 32-byte key produced by `wrapKeyWithNonce`.
pub fn unwrapKeyWithNonce(
    kek: [KEY_LEN]u8,
    wrapped: [WRAPPED_KEY_WITH_NONCE_LEN]u8,
    aad: []const u8,
) ![KEY_LEN]u8 {
    const nonce = wrapped[0..XCHACHA_NONCE_LEN].*;
    const ciphertext = wrapped[XCHACHA_NONCE_LEN..][0..KEY_LEN];
    const tag = wrapped[XCHACHA_NONCE_LEN + KEY_LEN ..][0..TAG_LEN].*;

    var out: [KEY_LEN]u8 = undefined;
    try XChaCha20Poly1305.decrypt(&out, ciphertext, tag, aad, nonce, kek);
    return out;
}

/// Encrypts an arbitrary-length blob (e.g. `vfs_catalog.db` or `credentials_wrapped`)
/// formatted as `nonce[24] || ciphertext[len] || tag[16]`.
pub fn encryptBlobWithNonce(
    allocator: std.mem.Allocator,
    io: std.Io,
    key: [KEY_LEN]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    const out = try allocator.alloc(u8, XCHACHA_NONCE_LEN + plaintext.len + TAG_LEN);
    errdefer allocator.free(out);

    var nonce: [XCHACHA_NONCE_LEN]u8 = undefined;
    io.random(&nonce);
    @memcpy(out[0..XCHACHA_NONCE_LEN], &nonce);

    var tag: [TAG_LEN]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        out[XCHACHA_NONCE_LEN..][0..plaintext.len],
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );
    @memcpy(out[XCHACHA_NONCE_LEN + plaintext.len ..][0..TAG_LEN], &tag);
    return out;
}

/// Decrypts a blob produced by `encryptBlobWithNonce`.
pub fn decryptBlobWithNonce(
    allocator: std.mem.Allocator,
    key: [KEY_LEN]u8,
    sealed: []const u8,
    aad: []const u8,
) ![]u8 {
    if (sealed.len < XCHACHA_NONCE_LEN + TAG_LEN) return error.InvalidSealedBlob;

    const plaintext_len = sealed.len - XCHACHA_NONCE_LEN - TAG_LEN;
    const nonce = sealed[0..XCHACHA_NONCE_LEN].*;
    const ciphertext = sealed[XCHACHA_NONCE_LEN..][0..plaintext_len];
    const tag = sealed[XCHACHA_NONCE_LEN + plaintext_len ..][0..TAG_LEN].*;

    const out = try allocator.alloc(u8, plaintext_len);
    errdefer allocator.free(out);

    try XChaCha20Poly1305.decrypt(out, ciphertext, tag, aad, nonce, key);
    return out;
}

/// Derives a per-part encryption key via `HKDF-SHA256(ikm = file_dek, salt = inode_ulid, info = "gdrive_vfs_part_v1" || le_u32(part_index))`.
pub fn derivePartKey(file_dek: [KEY_LEN]u8, inode_ulid: [16]u8, part_index: u32) [KEY_LEN]u8 {
    const prk = HkdfSha256.extract(&inode_ulid, &file_dek);
    var info: ["gdrive_vfs_part_v1".len + 4]u8 = undefined;
    @memcpy(info[0.."gdrive_vfs_part_v1".len], "gdrive_vfs_part_v1");
    std.mem.writeInt(u32, info["gdrive_vfs_part_v1".len..][0..4], part_index, .little);

    var out: [KEY_LEN]u8 = undefined;
    HkdfSha256.expand(&out, &info, prk);
    return out;
}

pub const GDRVPART_MAGIC: [8]u8 = .{ 'G', 'D', 'R', 'V', 'P', 'A', 'R', 'T' };
pub const GDRVPART_HEADER_LEN: usize = 64;

pub const HeaderFlags = packed struct(u16) {
    per_page_adaptive: bool = false,
    reserved: u15 = 0,
};

/// 64-byte fixed header at offset 0..63 of every `.part` blob (`037` §5.3).
pub const GdrvPartHeader = struct {
    magic: [8]u8 = GDRVPART_MAGIC,
    version: u16 = 1,
    flags: HeaderFlags = .{},
    page_size: u32 = PAGE_SIZE_BYTES,
    page_count: u32 = 0,
    nonce_prefix: [16]u8 = @splat(0),
    index_offset: u64 = 0,
    index_cipher_len: u32 = 0,
    reserved: [16]u8 = @splat(0),

    pub fn toBytes(self: GdrvPartHeader) [GDRVPART_HEADER_LEN]u8 {
        var buf: [GDRVPART_HEADER_LEN]u8 = @splat(0);
        @memcpy(buf[0..8], &self.magic);
        std.mem.writeInt(u16, buf[8..10], self.version, .little);
        std.mem.writeInt(u16, buf[10..12], @bitCast(self.flags), .little);
        std.mem.writeInt(u32, buf[12..16], self.page_size, .little);
        std.mem.writeInt(u32, buf[16..20], self.page_count, .little);
        @memcpy(buf[20..36], &self.nonce_prefix);
        std.mem.writeInt(u64, buf[36..44], self.index_offset, .little);
        std.mem.writeInt(u32, buf[44..48], self.index_cipher_len, .little);
        @memcpy(buf[48..64], &self.reserved);
        return buf;
    }

    pub fn fromBytes(buf: *const [GDRVPART_HEADER_LEN]u8) !GdrvPartHeader {
        if (!std.mem.eql(u8, buf[0..8], &GDRVPART_MAGIC)) return error.InvalidPartMagic;
        const version = std.mem.readInt(u16, buf[8..10], .little);
        if (version != 1) return error.UnsupportedPartVersion;
        const flags_raw = std.mem.readInt(u16, buf[10..12], .little);
        return .{
            .magic = buf[0..8].*,
            .version = version,
            .flags = @bitCast(flags_raw),
            .page_size = std.mem.readInt(u32, buf[12..16], .little),
            .page_count = std.mem.readInt(u32, buf[16..20], .little),
            .nonce_prefix = buf[20..36].*,
            .index_offset = std.mem.readInt(u64, buf[36..44], .little),
            .index_cipher_len = std.mem.readInt(u32, buf[44..48], .little),
            .reserved = buf[48..64].*,
        };
    }
};

fn buildPageNonce(nonce_prefix: [16]u8, page_index: u64) [XCHACHA_NONCE_LEN]u8 {
    var nonce: [XCHACHA_NONCE_LEN]u8 = undefined;
    @memcpy(nonce[0..16], &nonce_prefix);
    std.mem.writeInt(u64, nonce[16..24], page_index, .little);
    return nonce;
}

fn buildPageAad(inode_ulid: [16]u8, part_index: u32, page_index: u64, is_last_page: bool) [29]u8 {
    var aad: [29]u8 = undefined;
    @memcpy(aad[0..16], &inode_ulid);
    std.mem.writeInt(u32, aad[16..20], part_index, .little);
    std.mem.writeInt(u64, aad[20..28], page_index, .little);
    aad[28] = if (is_last_page) 1 else 0;
    return aad;
}

/// Encrypts a single page into `out_sealed` (must have length `plaintext.len + TAG_LEN`).
pub fn encryptPage(
    part_key: [KEY_LEN]u8,
    inode_ulid: [16]u8,
    part_index: u32,
    page_index: u64,
    is_last_page: bool,
    nonce_prefix: [16]u8,
    plaintext: []const u8,
    out_sealed: []u8,
) void {
    std.debug.assert(out_sealed.len == plaintext.len + TAG_LEN);
    const nonce = buildPageNonce(nonce_prefix, page_index);
    const aad = buildPageAad(inode_ulid, part_index, page_index, is_last_page);

    var tag: [TAG_LEN]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        out_sealed[0..plaintext.len],
        &tag,
        plaintext,
        &aad,
        nonce,
        part_key,
    );
    @memcpy(out_sealed[plaintext.len..][0..TAG_LEN], &tag);
}

/// Decrypts and authenticates a single page into `out_plaintext` (must have length `sealed.len - TAG_LEN`).
pub fn decryptPage(
    part_key: [KEY_LEN]u8,
    inode_ulid: [16]u8,
    part_index: u32,
    page_index: u64,
    is_last_page: bool,
    nonce_prefix: [16]u8,
    sealed: []const u8,
    out_plaintext: []u8,
) !void {
    if (sealed.len < TAG_LEN) return error.InvalidSealedPage;
    const pt_len = sealed.len - TAG_LEN;
    std.debug.assert(out_plaintext.len == pt_len);

    const nonce = buildPageNonce(nonce_prefix, page_index);
    const aad = buildPageAad(inode_ulid, part_index, page_index, is_last_page);
    const tag = sealed[pt_len..][0..TAG_LEN].*;

    try XChaCha20Poly1305.decrypt(
        out_plaintext,
        sealed[0..pt_len],
        tag,
        &aad,
        nonce,
        part_key,
    );
}
