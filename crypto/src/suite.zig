const std = @import("std");

/// Stable numeric wire IDs for supported cryptographic cipher suites (`CR-01`).
pub const CipherSuiteId = enum(u16) {
    mlkem768_x25519_xchacha20_poly1305 = 1,
    mlkem768_x25519_aes256_gcm = 2,
    mlkem1024_aes256_gcm = 3,
    mlkem1024_xchacha20_poly1305 = 4,
    x25519_aes256_gcm = 5,
    x25519_xchacha20_poly1305 = 6,

    pub fn fromInt(raw: u16) error{UnsupportedCipherSuite}!CipherSuiteId {
        return std.enums.fromInt(CipherSuiteId, raw) orelse error.UnsupportedCipherSuite;
    }

    pub fn toInt(self: CipherSuiteId) u16 {
        return @intFromEnum(self);
    }

    pub fn meta(self: CipherSuiteId) CipherSuiteMeta {
        return getMeta(self);
    }
};

pub const KemAlgorithm = enum {
    mlkem768_x25519,
    mlkem1024,
    x25519,
};

pub const AeadAlgorithm = enum {
    xchacha20_poly1305,
    aes256_gcm,
};

/// Metadata describing key, nonce, tag, KEM sizes, and PQC status for a `CipherSuiteId` (`CR-02`).
pub const CipherSuiteMeta = struct {
    id: CipherSuiteId,
    name: []const u8,
    kem: KemAlgorithm,
    aead: AeadAlgorithm,
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
    kem_ciphertext_len: usize,
    is_pqc: bool,
};

pub fn getMeta(suite: CipherSuiteId) CipherSuiteMeta {
    const MlKem768X25519 = std.crypto.kem.hybrid.MlKem768X25519;
    const MlKem1024 = std.crypto.kem.ml_kem.MLKem1024;
    const X25519 = std.crypto.dh.X25519;

    return switch (suite) {
        .mlkem768_x25519_xchacha20_poly1305 => .{
            .id = suite,
            .name = "MLKEM768-X25519+XChaCha20-Poly1305",
            .kem = .mlkem768_x25519,
            .aead = .xchacha20_poly1305,
            .key_len = 32,
            .nonce_len = 24,
            .tag_len = 16,
            .kem_ciphertext_len = MlKem768X25519.EncapsulatedSecret.ciphertext_length,
            .is_pqc = true,
        },
        .mlkem768_x25519_aes256_gcm => .{
            .id = suite,
            .name = "MLKEM768-X25519+AES-256-GCM",
            .kem = .mlkem768_x25519,
            .aead = .aes256_gcm,
            .key_len = 32,
            .nonce_len = 12,
            .tag_len = 16,
            .kem_ciphertext_len = MlKem768X25519.EncapsulatedSecret.ciphertext_length,
            .is_pqc = true,
        },
        .mlkem1024_aes256_gcm => .{
            .id = suite,
            .name = "MLKEM1024+AES-256-GCM",
            .kem = .mlkem1024,
            .aead = .aes256_gcm,
            .key_len = 32,
            .nonce_len = 12,
            .tag_len = 16,
            .kem_ciphertext_len = MlKem1024.ciphertext_length,
            .is_pqc = true,
        },
        .mlkem1024_xchacha20_poly1305 => .{
            .id = suite,
            .name = "MLKEM1024+XChaCha20-Poly1305",
            .kem = .mlkem1024,
            .aead = .xchacha20_poly1305,
            .key_len = 32,
            .nonce_len = 24,
            .tag_len = 16,
            .kem_ciphertext_len = MlKem1024.ciphertext_length,
            .is_pqc = true,
        },
        .x25519_aes256_gcm => .{
            .id = suite,
            .name = "X25519+AES-256-GCM",
            .kem = .x25519,
            .aead = .aes256_gcm,
            .key_len = 32,
            .nonce_len = 12,
            .tag_len = 16,
            .kem_ciphertext_len = X25519.public_length,
            .is_pqc = false,
        },
        .x25519_xchacha20_poly1305 => .{
            .id = suite,
            .name = "X25519+XChaCha20-Poly1305",
            .kem = .x25519,
            .aead = .xchacha20_poly1305,
            .key_len = 32,
            .nonce_len = 24,
            .tag_len = 16,
            .kem_ciphertext_len = X25519.public_length,
            .is_pqc = false,
        },
    };
}

test "CipherSuiteId wire IDs and metadata lookup" {
    const def = CipherSuiteId.mlkem768_x25519_xchacha20_poly1305;
    try std.testing.expectEqual(@as(u16, 1), def.toInt());
    try std.testing.expectEqual(def, try CipherSuiteId.fromInt(1));
    try std.testing.expectError(error.UnsupportedCipherSuite, CipherSuiteId.fromInt(999));

    const m = def.meta();
    try std.testing.expectEqual(@as(usize, 32), m.key_len);
    try std.testing.expectEqual(@as(usize, 24), m.nonce_len);
    try std.testing.expectEqual(@as(usize, 16), m.tag_len);
    try std.testing.expect(m.is_pqc);

    const classic = CipherSuiteId.x25519_aes256_gcm.meta();
    try std.testing.expect(!classic.is_pqc);
    try std.testing.expectEqual(@as(usize, 12), classic.nonce_len);
    try std.testing.expectEqual(@as(usize, 32), classic.kem_ciphertext_len);
}
