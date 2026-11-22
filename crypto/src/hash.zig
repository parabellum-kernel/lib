const std = @import("std");

/// Generic wrapper for fixed-digest cryptographic hashes supporting one-shot and streaming (`CR-03`).
fn DigestWrapper(comptime Impl: type) type {
    return struct {
        pub const digest_length: usize = Impl.digest_length;
        pub const block_length: usize = Impl.block_length;
        pub const Digest = [digest_length]u8;

        inner: Impl,

        pub fn init() @This() {
            return .{ .inner = Impl.init(.{}) };
        }

        pub fn update(self: *@This(), data: []const u8) void {
            self.inner.update(data);
        }

        pub fn final(self: *@This()) Digest {
            var out: Digest = undefined;
            self.inner.final(&out);
            return out;
        }

        pub fn hash(data: []const u8) Digest {
            var out: Digest = undefined;
            Impl.hash(data, &out, .{});
            return out;
        }
    };
}

/// Generic wrapper for 32-bit CRC checksums supporting one-shot and streaming (`CR-04`).
fn Crc32Wrapper(comptime Impl: type) type {
    return struct {
        inner: Impl,

        pub fn init() @This() {
            return .{ .inner = Impl.init() };
        }

        pub fn update(self: *@This(), data: []const u8) void {
            self.inner.update(data);
        }

        pub fn final(self: *@This()) u32 {
            return self.inner.final();
        }

        pub fn hash(data: []const u8) u32 {
            return Impl.hash(data);
        }
    };
}

pub const Sha256 = DigestWrapper(std.crypto.hash.sha2.Sha256);
pub const Sha512 = DigestWrapper(std.crypto.hash.sha2.Sha512);
/// Legacy SHA-1 strictly for RFC 4226/6238 OTP compatibility (`lib/otp`).
pub const Sha1 = DigestWrapper(std.crypto.hash.Sha1);
pub const Blake3 = DigestWrapper(std.crypto.hash.Blake3);

pub const Crc32 = Crc32Wrapper(std.hash.crc.@"CRC-32/ISO-HDLC");
pub const Crc32c = Crc32Wrapper(std.hash.crc.@"CRC-32/ISCSI");

test "SHA-256, SHA-512, SHA-1, BLAKE3 test vectors (one-shot and streaming)" {
    // NIST / RFC test vector for "abc"
    const sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const d256 = Sha256.hash("abc");
    try std.testing.expectEqualSlices(u8, sha256_abc, &std.fmt.bytesToHex(d256, .lower));

    var s256 = Sha256.init();
    s256.update("a");
    s256.update("bc");
    try std.testing.expectEqualSlices(u8, &d256, &s256.final());

    const sha1_abc = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const d1 = Sha1.hash("abc");
    try std.testing.expectEqualSlices(u8, sha1_abc, &std.fmt.bytesToHex(d1, .lower));

    const sha512_abc =
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    const d512 = Sha512.hash("abc");
    try std.testing.expectEqualSlices(u8, sha512_abc, &std.fmt.bytesToHex(d512, .lower));

    // BLAKE3 empty string official test vector
    const blake3_empty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const db3 = Blake3.hash("");
    try std.testing.expectEqualSlices(u8, blake3_empty, &std.fmt.bytesToHex(db3, .lower));

    var sb3 = Blake3.init();
    sb3.update("hello ");
    sb3.update("world");
    try std.testing.expectEqualSlices(u8, &Blake3.hash("hello world"), &sb3.final());
}

test "CRC32 (IEEE) and CRC32C (Castagnoli) test vectors" {
    const input = "123456789";
    try std.testing.expectEqual(@as(u32, 0xCBF43926), Crc32.hash(input));
    try std.testing.expectEqual(@as(u32, 0xE3069283), Crc32c.hash(input));

    var c = Crc32c.init();
    c.update("1234");
    c.update("56789");
    try std.testing.expectEqual(@as(u32, 0xE3069283), c.final());
}
