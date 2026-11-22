const std = @import("std");

pub const EncodingError = error{
    InvalidCharacter,
    InvalidLength,
    InvalidPadding,
    NoSpaceLeft,
};

/// RFC 4648 Base32 encoder/decoder (uppercase A-Z, 2-7, case-insensitive decode, optional `=` padding) (`CR-16`).
pub const Base32 = struct {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    pub fn calcEncodedSize(src_len: usize, padded: bool) usize {
        if (padded) {
            return ((src_len + 4) / 5) * 8;
        }
        const full_blocks = (src_len / 5) * 8;
        const rem = src_len % 5;
        const rem_chars: usize = switch (rem) {
            0 => 0,
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            else => unreachable,
        };
        return full_blocks + rem_chars;
    }

    pub fn calcMaxDecodedSize(encoded_len: usize) usize {
        return (encoded_len * 5) / 8;
    }

    pub fn encode(dst: []u8, src: []const u8, padded: bool) EncodingError![]const u8 {
        const needed = calcEncodedSize(src.len, padded);
        if (dst.len < needed) return error.NoSpaceLeft;

        var out_idx: usize = 0;
        var buffer: u16 = 0;
        var bits_left: u5 = 0;

        for (src) |b| {
            buffer = (buffer << 8) | b;
            bits_left += 8;
            while (bits_left >= 5) {
                bits_left -= 5;
                const shift: u4 = @intCast(bits_left);
                const idx: usize = @intCast((buffer >> shift) & 0x1F);
                dst[out_idx] = alphabet[idx];
                out_idx += 1;
            }
        }

        if (bits_left > 0) {
            const shift: u4 = @intCast(5 - bits_left);
            const idx: usize = @intCast((buffer << shift) & 0x1F);
            dst[out_idx] = alphabet[idx];
            out_idx += 1;
        }

        if (padded) {
            while (out_idx < needed) : (out_idx += 1) {
                dst[out_idx] = '=';
            }
        }

        return dst[0..out_idx];
    }

    pub fn encodeAlloc(allocator: std.mem.Allocator, src: []const u8, padded: bool) ![]u8 {
        const needed = calcEncodedSize(src.len, padded);
        const out = try allocator.alloc(u8, needed);
        errdefer allocator.free(out);
        _ = try encode(out, src, padded);
        return out;
    }

    fn decodeChar(c: u8) ?u5 {
        return switch (c) {
            'A'...'Z' => @intCast(c - 'A'),
            'a'...'z' => @intCast(c - 'a'),
            '2'...'7' => @intCast(c - '2' + 26),
            else => null,
        };
    }

    /// Decodes RFC 4648 Base32 (accepts uppercase/lowercase, with or without `=` padding).
    pub fn decode(dst: []u8, src: []const u8) EncodingError![]const u8 {
        var trimmed = src;
        while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '=') {
            trimmed = trimmed[0 .. trimmed.len - 1];
        }

        var buffer: u16 = 0;
        var bits_left: u5 = 0;
        var out_idx: usize = 0;

        for (trimmed) |c| {
            const val = decodeChar(c) orelse return error.InvalidCharacter;
            buffer = (buffer << 5) | val;
            bits_left += 5;
            if (bits_left >= 8) {
                bits_left -= 8;
                if (out_idx >= dst.len) return error.NoSpaceLeft;
                const shift: u4 = @intCast(bits_left);
                dst[out_idx] = @intCast((buffer >> shift) & 0xFF);
                out_idx += 1;
            }
        }

        // Remaining bits (< 5) must be zero per RFC 4648 §3.5
        if (bits_left > 0) {
            const shift: u4 = @intCast(bits_left);
            const mask = (@as(u16, 1) << shift) - 1;
            if ((buffer & mask) != 0) return error.InvalidPadding;
        }

        return dst[0..out_idx];
    }

    pub fn decodeAlloc(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
        const max_len = calcMaxDecodedSize(src.len);
        const buf = try allocator.alloc(u8, max_len);
        errdefer allocator.free(buf);
        const decoded = try decode(buf, src);
        return allocator.realloc(buf, decoded.len);
    }
};

/// RFC 4648 §5 Base64URL (unpadded) encoder/decoder (`CR-16`).
pub const Base64Url = struct {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const decoder = std.base64.url_safe_no_pad.Decoder;

    pub fn calcEncodedSize(src_len: usize) usize {
        return encoder.calcSize(src_len);
    }

    pub fn calcDecodedSize(src: []const u8) !usize {
        return decoder.calcSizeForSlice(src);
    }

    pub fn encode(dst: []u8, src: []const u8) EncodingError![]const u8 {
        const needed = encoder.calcSize(src.len);
        if (dst.len < needed) return error.NoSpaceLeft;
        return encoder.encode(dst, src);
    }

    pub fn encodeAlloc(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
        const needed = encoder.calcSize(src.len);
        const out = try allocator.alloc(u8, needed);
        _ = encoder.encode(out, src);
        return out;
    }

    pub fn decode(dst: []u8, src: []const u8) ![]const u8 {
        const needed = try decoder.calcSizeForSlice(src);
        if (dst.len < needed) return error.NoSpaceLeft;
        try decoder.decode(dst[0..needed], src);
        return dst[0..needed];
    }

    pub fn decodeAlloc(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
        const needed = try decoder.calcSizeForSlice(src);
        const out = try allocator.alloc(u8, needed);
        errdefer allocator.free(out);
        try decoder.decode(out, src);
        return out;
    }
};

test "Base32 RFC 4648 test vectors" {
    const alloc = std.testing.allocator;
    const cases = [_]struct { pt: []const u8, b32: []const u8 }{
        .{ .pt = "", .b32 = "" },
        .{ .pt = "f", .b32 = "MY======" },
        .{ .pt = "fo", .b32 = "MZXQ====" },
        .{ .pt = "foo", .b32 = "MZXW6===" },
        .{ .pt = "foob", .b32 = "MZXW6YQ=" },
        .{ .pt = "fooba", .b32 = "MZXW6YTB" },
        .{ .pt = "foobar", .b32 = "MZXW6YTBOI======" },
    };
    for (cases) |c| {
        const enc = try Base32.encodeAlloc(alloc, c.pt, true);
        defer alloc.free(enc);
        try std.testing.expectEqualStrings(c.b32, enc);

        const dec = try Base32.decodeAlloc(alloc, enc);
        defer alloc.free(dec);
        try std.testing.expectEqualStrings(c.pt, dec);
    }
    // Lowercase & unpadded decode
    const dec2 = try Base32.decodeAlloc(alloc, "mzxw6ytboi");
    defer alloc.free(dec2);
    try std.testing.expectEqualStrings("foobar", dec2);
}

test "Base64Url roundtrip" {
    const alloc = std.testing.allocator;
    const raw = "\xfb\xff\xfe\x00\x01\x02";
    const enc = try Base64Url.encodeAlloc(alloc, raw);
    defer alloc.free(enc);
    try std.testing.expect(std.mem.indexOfAny(u8, enc, "+/=") == null);

    const dec = try Base64Url.decodeAlloc(alloc, enc);
    defer alloc.free(dec);
    try std.testing.expectEqualSlices(u8, raw, dec);
}
