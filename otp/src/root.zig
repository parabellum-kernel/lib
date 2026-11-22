const std = @import("std");
const crypto = @import("parabellum_crypto");

pub const OtpError = error{
    InvalidDigits,
    InvalidPeriod,
    InvalidTimestamp,
    BufferTooSmall,
};

pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,

    pub fn uriName(self: Algorithm) []const u8 {
        return switch (self) {
            .sha1 => "SHA1",
            .sha256 => "SHA256",
            .sha512 => "SHA512",
        };
    }
};

pub const HotpConfig = struct {
    digits: u8 = 6,
    algorithm: Algorithm = .sha1,
};

pub const TotpConfig = struct {
    digits: u8 = 6,
    period: u64 = 30,
    t0: i64 = 0,
    algorithm: Algorithm = .sha1,
    /// Number of time steps before and after the current step to accept (e.g., 1 => [step-1, step, step+1]).
    skew: u64 = 1,
};

fn pow10(digits: u8) OtpError!u32 {
    return switch (digits) {
        6 => 1_000_000,
        7 => 10_000_000,
        8 => 100_000_000,
        else => error.InvalidDigits,
    };
}

fn dynamicTruncate(digest: []const u8) u32 {
    const offset: usize = @intCast(digest[digest.len - 1] & 0x0f);
    const bin_code: u32 = (@as(u32, digest[offset] & 0x7f) << 24) |
        (@as(u32, digest[offset + 1]) << 16) |
        (@as(u32, digest[offset + 2]) << 8) |
        @as(u32, digest[offset + 3]);
    return bin_code;
}

/// Computes an RFC 4226 HOTP numeric code for `secret` and `counter`.
pub fn hotpCode(secret: []const u8, counter: u64, cfg: HotpConfig) OtpError!u32 {
    const mod = try pow10(cfg.digits);
    var counter_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_be, counter, .big);

    const truncated: u32 = switch (cfg.algorithm) {
        .sha1 => blk: {
            var mac = crypto.HmacSha1.create(secret, &counter_be);
            defer crypto.secureZero(&mac);
            break :blk dynamicTruncate(&mac);
        },
        .sha256 => blk: {
            var mac = crypto.HmacSha256.create(secret, &counter_be);
            defer crypto.secureZero(&mac);
            break :blk dynamicTruncate(&mac);
        },
        .sha512 => blk: {
            var mac = crypto.HmacSha512.create(secret, &counter_be);
            defer crypto.secureZero(&mac);
            break :blk dynamicTruncate(&mac);
        },
    };
    return truncated % mod;
}

/// Formats an RFC 4226 HOTP code as zero-padded ASCII digits into `out`.
pub fn hotpFormat(secret: []const u8, counter: u64, cfg: HotpConfig, out: []u8) OtpError![]const u8 {
    if (out.len < cfg.digits) return error.BufferTooSmall;
    var code = try hotpCode(secret, counter, cfg);
    var i: usize = cfg.digits;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast('0' + (code % 10));
        code /= 10;
    }
    return out[0..cfg.digits];
}

/// Verifies an HOTP ASCII code in constant time.
pub fn verifyHotp(secret: []const u8, counter: u64, code: []const u8, cfg: HotpConfig) OtpError!bool {
    _ = try pow10(cfg.digits);
    if (code.len != cfg.digits) return false;
    var expected_buf: [8]u8 = undefined;
    defer crypto.secureZero(&expected_buf);
    const expected = try hotpFormat(secret, counter, cfg, &expected_buf);
    return crypto.constantTimeEql(expected, code);
}

/// Computes the RFC 6238 time step `T = floor((timestamp - t0) / period)`.
pub fn totpStep(timestamp: i64, period: u64, t0: i64) OtpError!u64 {
    if (period == 0) return error.InvalidPeriod;
    if (timestamp < t0) return error.InvalidTimestamp;
    const elapsed: u64 = @intCast(timestamp - t0);
    return elapsed / period;
}

/// Computes an RFC 6238 TOTP numeric code for `secret` at Unix `timestamp`.
pub fn totpCode(secret: []const u8, timestamp: i64, cfg: TotpConfig) OtpError!u32 {
    const step = try totpStep(timestamp, cfg.period, cfg.t0);
    return hotpCode(secret, step, .{ .digits = cfg.digits, .algorithm = cfg.algorithm });
}

/// Formats an RFC 6238 TOTP code as zero-padded ASCII digits into `out`.
pub fn totpFormat(secret: []const u8, timestamp: i64, cfg: TotpConfig, out: []u8) OtpError![]const u8 {
    const step = try totpStep(timestamp, cfg.period, cfg.t0);
    return hotpFormat(secret, step, .{ .digits = cfg.digits, .algorithm = cfg.algorithm }, out);
}

/// Verifies a TOTP code across `[step - skew, step + skew]` in constant time.
/// Returns the matched time step on success (for replay tracking) or `null` if invalid.
pub fn verifyTotp(secret: []const u8, timestamp: i64, code: []const u8, cfg: TotpConfig) OtpError!?u64 {
    _ = try pow10(cfg.digits);
    const base_step = try totpStep(timestamp, cfg.period, cfg.t0);
    if (code.len != cfg.digits) return null;

    const min_step = base_step -| cfg.skew;
    const max_step = base_step +| cfg.skew;

    var matched_step: ?u64 = null;
    var expected_buf: [8]u8 = undefined;
    defer crypto.secureZero(&expected_buf);

    var s = min_step;
    while (s <= max_step) : (s += 1) {
        const expected = try hotpFormat(secret, s, .{ .digits = cfg.digits, .algorithm = cfg.algorithm }, &expected_buf);
        if (crypto.constantTimeEql(expected, code) and matched_step == null) {
            matched_step = s;
        }
    }
    return matched_step;
}

/// Decodes an unpadded/padded Base32 secret (as used by authenticator apps).
pub fn decodeBase32Secret(allocator: std.mem.Allocator, b32_secret: []const u8) ![]u8 {
    return crypto.Base32.decodeAlloc(allocator, b32_secret);
}

/// Encodes a raw secret into unpadded Base32.
pub fn encodeBase32Secret(allocator: std.mem.Allocator, raw_secret: []const u8) ![]u8 {
    return crypto.Base32.encodeAlloc(allocator, raw_secret, false);
}

/// Formats a provisioning URI: `otpauth://totp/<issuer>:<account>?secret=...&issuer=...&algorithm=...&digits=...&period=...`.
pub fn formatOtpAuthUri(
    allocator: std.mem.Allocator,
    issuer: []const u8,
    account: []const u8,
    raw_secret: []const u8,
    cfg: TotpConfig,
) ![]u8 {
    _ = try pow10(cfg.digits);
    if (cfg.period == 0) return error.InvalidPeriod;

    const b32 = try encodeBase32Secret(allocator, raw_secret);
    defer {
        crypto.secureZero(b32);
        allocator.free(b32);
    }

    return std.fmt.allocPrint(
        allocator,
        "otpauth://totp/{s}:{s}?secret={s}&issuer={s}&algorithm={s}&digits={d}&period={d}",
        .{ issuer, account, b32, issuer, cfg.algorithm.uriName(), cfg.digits, cfg.period },
    );
}

test "RFC 4226 Appendix D HOTP test vectors" {
    const secret = "12345678901234567890";
    const expected = [_][]const u8{
        "755224", "287082", "359152", "969429", "338314",
        "254676", "287922", "162583", "399871", "520489",
    };
    var buf: [8]u8 = undefined;
    for (expected, 0..) |exp, counter| {
        const got = try hotpFormat(secret, @intCast(counter), .{}, &buf);
        try std.testing.expectEqualStrings(exp, got);
        try std.testing.expect(try verifyHotp(secret, @intCast(counter), exp, .{}));
    }
    try std.testing.expect(!try verifyHotp(secret, 0, "000000", .{}));
}

test "RFC 6238 Appendix B TOTP test vectors (SHA1, SHA256, SHA512)" {
    const secret_sha1 = "12345678901234567890";
    const secret_sha256 = "12345678901234567890123456789012";
    const secret_sha512 = "1234567890123456789012345678901234567890123456789012345678901234";

    const Case = struct {
        ts: i64,
        sha1: []const u8,
        sha256: []const u8,
        sha512: []const u8,
    };
    const cases = [_]Case{
        .{ .ts = 59, .sha1 = "94287082", .sha256 = "46119246", .sha512 = "90693936" },
        .{ .ts = 1111111109, .sha1 = "07081804", .sha256 = "68084774", .sha512 = "25091201" },
        .{ .ts = 1111111111, .sha1 = "14050471", .sha256 = "67062674", .sha512 = "99943326" },
        .{ .ts = 1234567890, .sha1 = "89005924", .sha256 = "91819424", .sha512 = "93441116" },
        .{ .ts = 2000000000, .sha1 = "69279037", .sha256 = "90698825", .sha512 = "38618901" },
        .{ .ts = 20000000000, .sha1 = "65353130", .sha256 = "77737706", .sha512 = "47863826" },
    };

    var buf: [8]u8 = undefined;
    for (cases) |c| {
        try std.testing.expectEqualStrings(c.sha1, try totpFormat(secret_sha1, c.ts, .{ .digits = 8, .algorithm = .sha1 }, &buf));
        try std.testing.expectEqualStrings(c.sha256, try totpFormat(secret_sha256, c.ts, .{ .digits = 8, .algorithm = .sha256 }, &buf));
        try std.testing.expectEqualStrings(c.sha512, try totpFormat(secret_sha512, c.ts, .{ .digits = 8, .algorithm = .sha512 }, &buf));
    }

    // Skew verification: code at ts=30 (step 1) should verify at ts=60 (step 2) with skew=1
    const step1_code = try totpFormat(secret_sha1, 30, .{}, &buf);
    var step1_copy: [6]u8 = undefined;
    @memcpy(&step1_copy, step1_code);
    const matched = try verifyTotp(secret_sha1, 60, &step1_copy, .{ .skew = 1 });
    try std.testing.expectEqual(@as(?u64, 1), matched);
    try std.testing.expectEqual(@as(?u64, null), try verifyTotp(secret_sha1, 90, &step1_copy, .{ .skew = 1 }));
}

test "Base32 secret and otpauth URI" {
    const alloc = std.testing.allocator;
    const raw = "12345678901234567890";
    const uri = try formatOtpAuthUri(alloc, "Parabellum", "alice@example.com", raw, .{});
    defer alloc.free(uri);
    try std.testing.expectEqualStrings(
        "otpauth://totp/Parabellum:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Parabellum&algorithm=SHA1&digits=6&period=30",
        uri,
    );

    const decoded = try decodeBase32Secret(alloc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    defer alloc.free(decoded);
    try std.testing.expectEqualStrings(raw, decoded);
}
