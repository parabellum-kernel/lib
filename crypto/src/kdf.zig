const std = @import("std");
const hygiene = @import("hygiene.zig");

/// Generic HMAC wrapper supporting one-shot `create`, streaming `init`/`update`/`final`, and `verify` (`CR-05`).
fn HmacWrapper(comptime Impl: type) type {
    return struct {
        pub const mac_length: usize = Impl.mac_length;
        pub const Mac = [mac_length]u8;

        inner: Impl,

        pub fn init(key: []const u8) @This() {
            return .{ .inner = Impl.init(key) };
        }

        pub fn update(self: *@This(), msg: []const u8) void {
            self.inner.update(msg);
        }

        pub fn final(self: *@This()) Mac {
            var out: Mac = undefined;
            self.inner.final(&out);
            return out;
        }

        pub fn create(key: []const u8, msg: []const u8) Mac {
            var out: Mac = undefined;
            Impl.create(&out, msg, key);
            return out;
        }

        pub fn verify(key: []const u8, msg: []const u8, expected: *const Mac) bool {
            var computed = create(key, msg);
            defer hygiene.secureZero(&computed);
            return hygiene.constantTimeEqlFixed(mac_length, &computed, expected);
        }
    };
}

pub const HmacSha256 = HmacWrapper(std.crypto.auth.hmac.sha2.HmacSha256);
pub const HmacSha512 = HmacWrapper(std.crypto.auth.hmac.sha2.HmacSha512);
/// Legacy HMAC-SHA1 strictly for RFC 4226/6238 OTP compatibility.
pub const HmacSha1 = HmacWrapper(std.crypto.auth.hmac.HmacSha1);

/// HKDF-SHA256 (`CR-06`) with explicit domain-separation `info`.
pub const HkdfSha256 = struct {
    const Impl = std.crypto.kdf.hkdf.HkdfSha256;
    pub const prk_length: usize = Impl.prk_length;

    pub fn extract(salt: []const u8, ikm: []const u8) [prk_length]u8 {
        return Impl.extract(salt, ikm);
    }

    pub fn expand(out: []u8, info: []const u8, prk: [prk_length]u8) void {
        Impl.expand(out, info, prk);
    }

    pub fn deriveKey(comptime len: usize, salt: []const u8, ikm: []const u8, info: []const u8) [len]u8 {
        var prk = extract(salt, ikm);
        defer hygiene.secureZero(&prk);
        var out: [len]u8 = undefined;
        expand(&out, info, prk);
        return out;
    }
};

/// Argon2id password-based KDF and PHC string hashing (`CR-07`).
pub const Argon2 = struct {
    pub const Params = std.crypto.pwhash.argon2.Params;
    pub const Mode = std.crypto.pwhash.argon2.Mode;

    pub fn deriveKey(
        allocator: std.mem.Allocator,
        io: std.Io,
        out_key: []u8,
        password: []const u8,
        salt: []const u8,
        params: Params,
    ) !void {
        try std.crypto.pwhash.argon2.kdf(allocator, out_key, password, salt, params, .argon2id, io);
    }

    pub fn hashPassword(
        allocator: std.mem.Allocator,
        io: std.Io,
        password: []const u8,
        params: Params,
        out_phc: []u8,
    ) ![]const u8 {
        return std.crypto.pwhash.argon2.strHash(
            password,
            .{ .allocator = allocator, .params = params, .mode = .argon2id },
            out_phc,
            io,
        );
    }

    pub fn verifyPassword(
        allocator: std.mem.Allocator,
        io: std.Io,
        phc_str: []const u8,
        password: []const u8,
    ) bool {
        std.crypto.pwhash.argon2.strVerify(phc_str, password, .{ .allocator = allocator }, io) catch return false;
        return true;
    }
};

/// Scrypt password-based KDF (`CR-07`).
pub const Scrypt = struct {
    pub const Params = std.crypto.pwhash.scrypt.Params;

    pub fn deriveKey(
        allocator: std.mem.Allocator,
        out_key: []u8,
        password: []const u8,
        salt: []const u8,
        params: Params,
    ) !void {
        try std.crypto.pwhash.scrypt.kdf(allocator, out_key, password, salt, params);
    }
};

test "HMAC-SHA256 RFC 4231 test vector 1 and streaming" {
    const key: [20]u8 = @splat(0x0b);
    const data = "Hi There";
    const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    const mac = HmacSha256.create(&key, data);
    try std.testing.expectEqualSlices(u8, expected, &std.fmt.bytesToHex(mac, .lower));
    try std.testing.expect(HmacSha256.verify(&key, data, &mac));

    var stream = HmacSha256.init(&key);
    stream.update("Hi ");
    stream.update("There");
    try std.testing.expectEqualSlices(u8, &mac, &stream.final());
}

test "HKDF-SHA256 RFC 5869 test vector 1" {
    const ikm: [22]u8 = @splat(0x0b);
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    const expected_okm =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" ++
        "34007208d5b887185865";

    const okm = HkdfSha256.deriveKey(42, &salt, &ikm, &info);
    try std.testing.expectEqualSlices(u8, expected_okm, &std.fmt.bytesToHex(okm, .lower));
}

test "Argon2id and Scrypt roundtrip" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var key1: [32]u8 = undefined;
    var key2: [32]u8 = undefined;
    const params = Argon2.Params{ .t = 1, .m = 32, .p = 1 };
    try Argon2.deriveKey(alloc, io, &key1, "correct-horse", "saltsalt", params);
    try Argon2.deriveKey(alloc, io, &key2, "correct-horse", "saltsalt", params);
    try std.testing.expectEqualSlices(u8, &key1, &key2);

    var phc_buf: [256]u8 = undefined;
    const phc = try Argon2.hashPassword(alloc, io, "correct-horse", params, &phc_buf);
    try std.testing.expect(Argon2.verifyPassword(alloc, io, phc, "correct-horse"));
    try std.testing.expect(!Argon2.verifyPassword(alloc, io, phc, "wrong-password"));

    var skey: [32]u8 = undefined;
    try Scrypt.deriveKey(alloc, &skey, "password", "NaCl", .{ .ln = 4, .r = 1, .p = 1 });
    try std.testing.expect(skey.len == 32);
}
