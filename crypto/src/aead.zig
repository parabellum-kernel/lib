const std = @import("std");
const suite_mod = @import("suite.zig");
const hygiene = @import("hygiene.zig");

pub const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
pub const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const WRAPPED_KEY_WITH_NONCE_LEN: usize = XCHACHA_NONCE_LEN + KEY_LEN + TAG_LEN;

pub const AeadError = error{
    InvalidSealedBlob,
    UnsupportedCipherSuite,
    AuthenticationFailed,
};

/// Wraps a 32-byte key using a reusable 32-byte KEK and random 24-byte nonce (`XChaCha20-Poly1305`, `CR-09`).
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

/// Unwraps a 32-byte key produced by `wrapKeyWithNonce` (`CR-09`).
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

/// Generic blob encryption (`nonce || ciphertext || tag`) parameterized by AEAD implementation (`CR-08`, `CR-09`).
fn encryptBlobImpl(
    comptime Impl: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    key: [KEY_LEN]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    const nonce_len = Impl.nonce_length;
    const tag_len = Impl.tag_length;
    const out = try allocator.alloc(u8, nonce_len + plaintext.len + tag_len);
    errdefer allocator.free(out);

    var nonce: [nonce_len]u8 = undefined;
    io.random(&nonce);
    @memcpy(out[0..nonce_len], &nonce);

    var tag: [tag_len]u8 = undefined;
    Impl.encrypt(
        out[nonce_len..][0..plaintext.len],
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );
    @memcpy(out[nonce_len + plaintext.len ..][0..tag_len], &tag);
    return out;
}

/// Generic blob decryption (`nonce || ciphertext || tag`) parameterized by AEAD implementation.
fn decryptBlobImpl(
    comptime Impl: type,
    allocator: std.mem.Allocator,
    key: [KEY_LEN]u8,
    sealed: []const u8,
    aad: []const u8,
) ![]u8 {
    const nonce_len = Impl.nonce_length;
    const tag_len = Impl.tag_length;
    if (sealed.len < nonce_len + tag_len) return error.InvalidSealedBlob;

    const plaintext_len = sealed.len - nonce_len - tag_len;
    const nonce = sealed[0..nonce_len].*;
    const ciphertext = sealed[nonce_len..][0..plaintext_len];
    const tag = sealed[nonce_len + plaintext_len ..][0..tag_len].*;

    const out = try allocator.alloc(u8, plaintext_len);
    errdefer allocator.free(out);

    try Impl.decrypt(out, ciphertext, tag, aad, nonce, key);
    return out;
}

/// Encrypts an arbitrary-length blob using `XChaCha20-Poly1305` (`nonce[24] || ciphertext || tag[16]`).
pub fn encryptBlobWithNonce(
    allocator: std.mem.Allocator,
    io: std.Io,
    key: [KEY_LEN]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    return encryptBlobImpl(XChaCha20Poly1305, allocator, io, key, plaintext, aad);
}

/// Decrypts a blob produced by `encryptBlobWithNonce`.
pub fn decryptBlobWithNonce(
    allocator: std.mem.Allocator,
    key: [KEY_LEN]u8,
    sealed: []const u8,
    aad: []const u8,
) ![]u8 {
    return decryptBlobImpl(XChaCha20Poly1305, allocator, key, sealed, aad);
}

/// Encrypts an arbitrary-length blob using the AEAD algorithm specified by `suite` (`CR-09`).
pub fn encryptBlobWithSuite(
    allocator: std.mem.Allocator,
    io: std.Io,
    suite: suite_mod.CipherSuiteId,
    key: [KEY_LEN]u8,
    plaintext: []const u8,
    aad: []const u8,
) ![]u8 {
    return switch (suite.meta().aead) {
        .xchacha20_poly1305 => encryptBlobImpl(XChaCha20Poly1305, allocator, io, key, plaintext, aad),
        .aes256_gcm => encryptBlobImpl(Aes256Gcm, allocator, io, key, plaintext, aad),
    };
}

/// Decrypts an arbitrary-length blob produced by `encryptBlobWithSuite` (`CR-09`).
pub fn decryptBlobWithSuite(
    allocator: std.mem.Allocator,
    suite: suite_mod.CipherSuiteId,
    key: [KEY_LEN]u8,
    sealed: []const u8,
    aad: []const u8,
) ![]u8 {
    return switch (suite.meta().aead) {
        .xchacha20_poly1305 => decryptBlobImpl(XChaCha20Poly1305, allocator, key, sealed, aad),
        .aes256_gcm => decryptBlobImpl(Aes256Gcm, allocator, key, sealed, aad),
    };
}

test "wrapKeyWithNonce / unwrapKeyWithNonce and suite AEAD roundtrip" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var kek = hygiene.SecretBytes(KEY_LEN).init(@splat(0x11));
    defer kek.deinit();
    var dek = hygiene.SecretBytes(KEY_LEN).init(@splat(0x22));
    defer dek.deinit();

    const wrapped = wrapKeyWithNonce(io, kek.bytes().*, dek.bytes().*, "aad:dek");
    const unwrapped = try unwrapKeyWithNonce(kek.bytes().*, wrapped, "aad:dek");
    try std.testing.expectEqualSlices(u8, dek.bytes(), &unwrapped);
    try std.testing.expectError(error.AuthenticationFailed, unwrapKeyWithNonce(kek.bytes().*, wrapped, "wrong-aad"));

    const suites = [_]suite_mod.CipherSuiteId{
        .mlkem768_x25519_xchacha20_poly1305,
        .mlkem768_x25519_aes256_gcm,
    };
    for (suites) |s| {
        const sealed = try encryptBlobWithSuite(alloc, io, s, kek.bytes().*, "secret payload", "ctx");
        defer alloc.free(sealed);
        const pt = try decryptBlobWithSuite(alloc, s, kek.bytes().*, sealed, "ctx");
        defer alloc.free(pt);
        try std.testing.expectEqualStrings("secret payload", pt);
    }
}

test "AES-256-GCM NIST test vector" {
    const key: [32]u8 = @splat(0);
    const nonce: [12]u8 = @splat(0);
    const pt = "";
    var ct: [0]u8 = .{};
    var tag: [16]u8 = undefined;
    Aes256Gcm.encrypt(&ct, &tag, pt, "", nonce, key);
    const expected_tag = "530f8afbc74536b9a963b4f1c4cb738b";
    try std.testing.expectEqualSlices(u8, expected_tag, &std.fmt.bytesToHex(tag, .lower));
}
