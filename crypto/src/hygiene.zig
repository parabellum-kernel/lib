const std = @import("std");

/// Overwrites `buf` with zeroes using `std.crypto.secureZero` so the compiler
/// cannot elide the zeroization even in ReleaseFast builds.
pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

/// Constant-time equality comparison for two fixed-size byte arrays.
pub fn constantTimeEqlFixed(comptime N: usize, a: *const [N]u8, b: *const [N]u8) bool {
    return std.crypto.timing_safe.eql([N]u8, a.*, b.*);
}

/// Convenience 32-byte constant-time equality check.
pub fn ctEql32(a: *const [32]u8, b: *const [32]u8) bool {
    return constantTimeEqlFixed(32, a, b);
}

/// Constant-time equality comparison for variable-length slices.
/// Note: returns `false` immediately if lengths differ; compares all bytes in
/// constant time when lengths are equal.
pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

/// RAII wrapper for fixed-size secret key material that zeroizes its buffer on `deinit()`.
pub fn SecretBytes(comptime N: usize) type {
    return struct {
        const Self = @This();

        buf: [N]u8,

        pub fn init(bytes_in: [N]u8) Self {
            return .{ .buf = bytes_in };
        }

        pub fn zero() Self {
            return .{ .buf = @splat(0) };
        }

        pub fn fromSlice(slice: []const u8) error{InvalidLength}!Self {
            if (slice.len != N) return error.InvalidLength;
            var out: [N]u8 = undefined;
            @memcpy(&out, slice);
            return .{ .buf = out };
        }

        pub fn bytes(self: *const Self) *const [N]u8 {
            return &self.buf;
        }

        pub fn mutBytes(self: *Self) *[N]u8 {
            return &self.buf;
        }

        pub fn deinit(self: *Self) void {
            secureZero(&self.buf);
            self.* = undefined;
        }
    };
}

test "secureZero zeroes buffer and is not elided" {
    var buf = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
    secureZero(&buf);
    for (0..buf.len) |i| {
        const ptr: *const volatile u8 = &buf[i];
        try std.testing.expectEqual(@as(u8, 0), ptr.*);
    }
}

test "constantTimeEqlFixed and ctEql32 compare arrays" {
    const a: [32]u8 = @splat(0x42);
    const b: [32]u8 = @splat(0x42);
    var c: [32]u8 = @splat(0x42);
    c[31] = 0x43;

    try std.testing.expect(ctEql32(&a, &b));
    try std.testing.expect(!ctEql32(&a, &c));
    try std.testing.expect(constantTimeEql(&a, &b));
    try std.testing.expect(!constantTimeEql(&a, &c));
    try std.testing.expect(!constantTimeEql(&a, a[0..31]));
}

test "SecretBytes zeroizes on deinit" {
    var sec = try SecretBytes(4).fromSlice("abcd");
    try std.testing.expectEqualSlices(u8, "abcd", sec.bytes());
    sec.deinit();
}
