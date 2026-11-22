const std = @import("std");
const crypto = @import("parabellum_crypto");

/// Overwrites `buf` with zeroes using `parabellum_crypto.secureZero` so the
/// compiler cannot elide the zeroization even in ReleaseFast builds.
pub fn wipe(buf: []u8) void {
    crypto.secureZero(buf);
}

/// Branchless constant-time comparison of two 32-byte arrays.
pub fn ctEql32(a: *const [32]u8, b: *const [32]u8) bool {
    return crypto.ctEql32(a, b);
}

test "wipe zeroes buffer and is not elided" {
    var buf = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44 };
    wipe(&buf);
    for (0..buf.len) |i| {
        const ptr: *const volatile u8 = &buf[i];
        try std.testing.expectEqual(@as(u8, 0), ptr.*);
    }
}

test "ctEql32 compares 32-byte arrays" {
    const a: [32]u8 = @splat(0x42);
    const b: [32]u8 = @splat(0x42);
    var c: [32]u8 = @splat(0x42);
    c[31] = 0x43;

    try std.testing.expect(ctEql32(&a, &b));
    try std.testing.expect(!ctEql32(&a, &c));
}
