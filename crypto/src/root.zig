pub const hygiene = @import("hygiene.zig");
pub const codec = @import("codec.zig");
pub const suite = @import("suite.zig");
pub const hash = @import("hash.zig");
pub const kdf = @import("kdf.zig");
pub const aead = @import("aead.zig");
pub const kem = @import("kem.zig");
pub const sign = @import("sign.zig");
pub const encoding = @import("encoding.zig");

pub const secureZero = hygiene.secureZero;
pub const constantTimeEql = hygiene.constantTimeEql;
pub const constantTimeEqlFixed = hygiene.constantTimeEqlFixed;
pub const ctEql32 = hygiene.ctEql32;
pub const SecretBytes = hygiene.SecretBytes;

pub const CodecError = codec.CodecError;
pub const BinaryWriter = codec.BinaryWriter;
pub const BinaryReader = codec.BinaryReader;

pub const CipherSuiteId = suite.CipherSuiteId;
pub const CipherSuiteMeta = suite.CipherSuiteMeta;
pub const KemAlgorithm = suite.KemAlgorithm;
pub const AeadAlgorithm = suite.AeadAlgorithm;

pub const Sha256 = hash.Sha256;
pub const Sha512 = hash.Sha512;
pub const Sha1 = hash.Sha1;
pub const Blake3 = hash.Blake3;
pub const Crc32 = hash.Crc32;
pub const Crc32c = hash.Crc32c;

pub const HmacSha256 = kdf.HmacSha256;
pub const HmacSha512 = kdf.HmacSha512;
pub const HmacSha1 = kdf.HmacSha1;
pub const HkdfSha256 = kdf.HkdfSha256;
pub const Argon2 = kdf.Argon2;
pub const Scrypt = kdf.Scrypt;

pub const XChaCha20Poly1305 = aead.XChaCha20Poly1305;
pub const Aes256Gcm = aead.Aes256Gcm;
pub const KEY_LEN = aead.KEY_LEN;
pub const TAG_LEN = aead.TAG_LEN;
pub const XCHACHA_NONCE_LEN = aead.XCHACHA_NONCE_LEN;
pub const AES_GCM_NONCE_LEN = aead.AES_GCM_NONCE_LEN;
pub const WRAPPED_KEY_WITH_NONCE_LEN = aead.WRAPPED_KEY_WITH_NONCE_LEN;
pub const wrapKeyWithNonce = aead.wrapKeyWithNonce;
pub const unwrapKeyWithNonce = aead.unwrapKeyWithNonce;
pub const encryptBlobWithNonce = aead.encryptBlobWithNonce;
pub const decryptBlobWithNonce = aead.decryptBlobWithNonce;
pub const encryptBlobWithSuite = aead.encryptBlobWithSuite;
pub const decryptBlobWithSuite = aead.decryptBlobWithSuite;

pub const MlKem768X25519 = kem.MlKem768X25519;
pub const MlKem1024 = kem.MlKem1024;
pub const X25519 = kem.X25519;
pub const RecipientPublicKey = kem.RecipientPublicKey;
pub const RecipientSecretKey = kem.RecipientSecretKey;
pub const WrappedRecipientKey = kem.WrappedRecipientKey;
pub const wrapKeyForRecipient = kem.wrapKeyForRecipient;
pub const unwrapKeyForRecipient = kem.unwrapKeyForRecipient;

pub const SignatureSchemeId = sign.SignatureSchemeId;
pub const Ed25519 = sign.Ed25519;

pub const EncodingError = encoding.EncodingError;
pub const Base32 = encoding.Base32;
pub const Base64Url = encoding.Base64Url;

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
