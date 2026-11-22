const std = @import("std");
const suite_mod = @import("suite.zig");
const aead = @import("aead.zig");
const kdf = @import("kdf.zig");
const hygiene = @import("hygiene.zig");

pub const MlKem768X25519 = std.crypto.kem.hybrid.MlKem768X25519;
pub const MlKem1024 = std.crypto.kem.ml_kem.MLKem1024;
pub const X25519 = std.crypto.dh.X25519;

pub const WRAPPED_KEY_LEN: usize = aead.KEY_LEN + aead.TAG_LEN;

pub const RecipientPublicKey = union(suite_mod.KemAlgorithm) {
    mlkem768_x25519: MlKem768X25519.PublicKey,
    mlkem1024: MlKem1024.PublicKey,
    x25519: [X25519.public_length]u8,
};

pub const RecipientSecretKey = union(suite_mod.KemAlgorithm) {
    mlkem768_x25519: MlKem768X25519.SecretKey,
    mlkem1024: MlKem1024.SecretKey,
    x25519: [X25519.secret_length]u8,
};

pub const WrappedRecipientKey = struct {
    suite: suite_mod.CipherSuiteId,
    kem_ciphertext: []u8,
    wrapped_key: [WRAPPED_KEY_LEN]u8,

    pub fn deinit(self: *WrappedRecipientKey, allocator: std.mem.Allocator) void {
        hygiene.secureZero(self.kem_ciphertext);
        allocator.free(self.kem_ciphertext);
        hygiene.secureZero(&self.wrapped_key);
        self.* = undefined;
    }
};

fn deriveX25519Kek(shared_secret: [X25519.shared_length]u8, eph_pk: [X25519.public_length]u8, rec_pk: [X25519.public_length]u8) [32]u8 {
    var ikm: [X25519.shared_length + X25519.public_length * 2]u8 = undefined;
    defer hygiene.secureZero(&ikm);
    @memcpy(ikm[0..32], &shared_secret);
    @memcpy(ikm[32..64], &eph_pk);
    @memcpy(ikm[64..96], &rec_pk);
    return kdf.HkdfSha256.deriveKey(32, "", &ikm, "parabellum_x25519_kem_v1");
}

fn wrapWithSharedSecret(
    suite: suite_mod.CipherSuiteId,
    shared_secret: [32]u8,
    key_to_wrap: [aead.KEY_LEN]u8,
    aad: []const u8,
) [WRAPPED_KEY_LEN]u8 {
    var out: [WRAPPED_KEY_LEN]u8 = undefined;
    var tag: [aead.TAG_LEN]u8 = undefined;
    switch (suite.meta().aead) {
        .xchacha20_poly1305 => {
            const zero_nonce: [aead.XCHACHA_NONCE_LEN]u8 = @splat(0);
            aead.XChaCha20Poly1305.encrypt(out[0..aead.KEY_LEN], &tag, &key_to_wrap, aad, zero_nonce, shared_secret);
        },
        .aes256_gcm => {
            const zero_nonce: [aead.AES_GCM_NONCE_LEN]u8 = @splat(0);
            aead.Aes256Gcm.encrypt(out[0..aead.KEY_LEN], &tag, &key_to_wrap, aad, zero_nonce, shared_secret);
        },
    }
    @memcpy(out[aead.KEY_LEN..], &tag);
    return out;
}

fn unwrapWithSharedSecret(
    suite: suite_mod.CipherSuiteId,
    shared_secret: [32]u8,
    wrapped_key: [WRAPPED_KEY_LEN]u8,
    aad: []const u8,
) ![aead.KEY_LEN]u8 {
    var out: [aead.KEY_LEN]u8 = undefined;
    const tag = wrapped_key[aead.KEY_LEN..][0..aead.TAG_LEN].*;
    switch (suite.meta().aead) {
        .xchacha20_poly1305 => {
            const zero_nonce: [aead.XCHACHA_NONCE_LEN]u8 = @splat(0);
            try aead.XChaCha20Poly1305.decrypt(&out, wrapped_key[0..aead.KEY_LEN], tag, aad, zero_nonce, shared_secret);
        },
        .aes256_gcm => {
            const zero_nonce: [aead.AES_GCM_NONCE_LEN]u8 = @splat(0);
            try aead.Aes256Gcm.decrypt(&out, wrapped_key[0..aead.KEY_LEN], tag, aad, zero_nonce, shared_secret);
        },
    }
    return out;
}

/// Encapsulates a fresh shared secret for `recipient_pk` using `suite` and wraps `key` with `aad` (`CR-10`, `CR-11`).
pub fn wrapKeyForRecipient(
    allocator: std.mem.Allocator,
    io: std.Io,
    suite: suite_mod.CipherSuiteId,
    key: [aead.KEY_LEN]u8,
    recipient_pk: RecipientPublicKey,
    aad: []const u8,
) !WrappedRecipientKey {
    const meta = suite.meta();
    if (std.meta.activeTag(recipient_pk) != meta.kem) return error.KeySuiteMismatch;

    switch (recipient_pk) {
        .mlkem768_x25519 => |pk| {
            const enc = try pk.encaps(io);
            var ss = enc.shared_secret;
            defer hygiene.secureZero(&ss);
            const ct = try allocator.dupe(u8, &enc.ciphertext);
            return .{
                .suite = suite,
                .kem_ciphertext = ct,
                .wrapped_key = wrapWithSharedSecret(suite, ss, key, aad),
            };
        },
        .mlkem1024 => |pk| {
            const enc = pk.encaps(io);
            var ss = enc.shared_secret;
            defer hygiene.secureZero(&ss);
            const ct = try allocator.dupe(u8, &enc.ciphertext);
            return .{
                .suite = suite,
                .kem_ciphertext = ct,
                .wrapped_key = wrapWithSharedSecret(suite, ss, key, aad),
            };
        },
        .x25519 => |rec_pk| {
            var eph_seed: [X25519.secret_length]u8 = undefined;
            io.random(&eph_seed);
            defer hygiene.secureZero(&eph_seed);

            var eph_kp = X25519.KeyPair.generateDeterministic(eph_seed);
            defer hygiene.secureZero(&eph_kp.secret_key);

            var raw_ss = try X25519.scalarmult(eph_kp.secret_key, rec_pk);
            defer hygiene.secureZero(&raw_ss);

            var kek = deriveX25519Kek(raw_ss, eph_kp.public_key, rec_pk);
            defer hygiene.secureZero(&kek);

            const ct = try allocator.dupe(u8, &eph_kp.public_key);
            return .{
                .suite = suite,
                .kem_ciphertext = ct,
                .wrapped_key = wrapWithSharedSecret(suite, kek, key, aad),
            };
        },
    }
}

/// Decapsulates the shared secret using `recipient_sk` and unwraps the key (`CR-10`, `CR-11`).
pub fn unwrapKeyForRecipient(
    recipient_sk: RecipientSecretKey,
    wrapped: WrappedRecipientKey,
    aad: []const u8,
) ![aead.KEY_LEN]u8 {
    const meta = wrapped.suite.meta();
    if (std.meta.activeTag(recipient_sk) != meta.kem) return error.KeySuiteMismatch;
    if (wrapped.kem_ciphertext.len != meta.kem_ciphertext_len) return error.InvalidKemCiphertext;

    switch (recipient_sk) {
        .mlkem768_x25519 => |sk| {
            var ss = try sk.decaps(wrapped.kem_ciphertext[0..MlKem768X25519.EncapsulatedSecret.ciphertext_length]);
            defer hygiene.secureZero(&ss);
            return unwrapWithSharedSecret(wrapped.suite, ss, wrapped.wrapped_key, aad);
        },
        .mlkem1024 => |sk| {
            var ss = try sk.decaps(wrapped.kem_ciphertext[0..MlKem1024.ciphertext_length]);
            defer hygiene.secureZero(&ss);
            return unwrapWithSharedSecret(wrapped.suite, ss, wrapped.wrapped_key, aad);
        },
        .x25519 => |sk| {
            const eph_pk = wrapped.kem_ciphertext[0..X25519.public_length].*;
            const rec_pk = X25519.recoverPublicKey(sk);
            var raw_ss = try X25519.scalarmult(sk, eph_pk);
            defer hygiene.secureZero(&raw_ss);

            var kek = deriveX25519Kek(raw_ss, eph_pk, rec_pk);
            defer hygiene.secureZero(&kek);
            return unwrapWithSharedSecret(wrapped.suite, kek, wrapped.wrapped_key, aad);
        },
    }
}

test "wrapKeyForRecipient / unwrapKeyForRecipient across MLKEM768-X25519, MLKEM1024, and X25519" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const vmk: [32]u8 = @splat(0x7A);
    const aad = "vault_01||slot_01";

    // 1. MLKEM768-X25519
    {
        const kp = try MlKem768X25519.KeyPair.generate(io);
        var wrapped = try wrapKeyForRecipient(alloc, io, .mlkem768_x25519_xchacha20_poly1305, vmk, .{ .mlkem768_x25519 = kp.public_key }, aad);
        defer wrapped.deinit(alloc);
        const out = try unwrapKeyForRecipient(.{ .mlkem768_x25519 = kp.secret_key }, wrapped, aad);
        try std.testing.expectEqualSlices(u8, &vmk, &out);
        try std.testing.expectError(error.AuthenticationFailed, unwrapKeyForRecipient(.{ .mlkem768_x25519 = kp.secret_key }, wrapped, "bad-aad"));
    }

    // 2. MLKEM1024 + AES-256-GCM
    {
        const kp = MlKem1024.KeyPair.generate(io);
        var wrapped = try wrapKeyForRecipient(alloc, io, .mlkem1024_aes256_gcm, vmk, .{ .mlkem1024 = kp.public_key }, aad);
        defer wrapped.deinit(alloc);
        const out = try unwrapKeyForRecipient(.{ .mlkem1024 = kp.secret_key }, wrapped, aad);
        try std.testing.expectEqualSlices(u8, &vmk, &out);
    }

    // 3. Classic X25519 + AES-256-GCM
    {
        const kp = X25519.KeyPair.generate(io);
        var wrapped = try wrapKeyForRecipient(alloc, io, .x25519_aes256_gcm, vmk, .{ .x25519 = kp.public_key }, aad);
        defer wrapped.deinit(alloc);
        const out = try unwrapKeyForRecipient(.{ .x25519 = kp.secret_key }, wrapped, aad);
        try std.testing.expectEqualSlices(u8, &vmk, &out);
    }
}
