const std = @import("std");

/// Signature scheme registry ready for future hybrid/PQC signatures (`CR-13`).
pub const SignatureSchemeId = enum(u16) {
    ed25519 = 1,
    ed25519_mldsa = 2,

    pub fn fromInt(raw: u16) error{UnsupportedSignatureScheme}!SignatureSchemeId {
        return std.enums.fromInt(SignatureSchemeId, raw) orelse error.UnsupportedSignatureScheme;
    }

    pub fn toInt(self: SignatureSchemeId) u16 {
        return @intFromEnum(self);
    }
};

/// Ed25519 digital signatures (`CR-12`).
pub const Ed25519 = struct {
    pub const Impl = std.crypto.sign.Ed25519;
    pub const KeyPair = Impl.KeyPair;
    pub const PublicKey = Impl.PublicKey;
    pub const SecretKey = Impl.SecretKey;
    pub const Signature = Impl.Signature;

    pub const public_length: usize = PublicKey.encoded_length;
    pub const secret_length: usize = SecretKey.encoded_length;
    pub const signature_length: usize = Signature.encoded_length;
    pub const seed_length: usize = KeyPair.seed_length;

    pub fn generate(io: std.Io) KeyPair {
        return KeyPair.generate(io);
    }

    pub fn generateDeterministic(seed: [seed_length]u8) !KeyPair {
        return KeyPair.generateDeterministic(seed);
    }

    pub fn sign(kp: KeyPair, msg: []const u8) !Signature {
        return kp.sign(msg, null);
    }

    pub fn verify(pk: PublicKey, msg: []const u8, sig: Signature) bool {
        sig.verify(msg, pk) catch return false;
        return true;
    }
};

test "Ed25519 sign and verify" {
    const io = std.testing.io;
    const kp = Ed25519.generate(io);
    const msg = "parabellum-catalog-commit-v1";
    const sig = try Ed25519.sign(kp, msg);
    try std.testing.expect(Ed25519.verify(kp.public_key, msg, sig));
    try std.testing.expect(!Ed25519.verify(kp.public_key, "tampered", sig));
}
