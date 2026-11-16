const std = @import("std");
const flate = std.compress.flate;

pub const CompressionMode = enum {
    none,
    whole_blob_deflate,
    per_page_adaptive,
};

pub const PageCodec = enum(u8) {
    raw = 0x00,
    deflate = 0x01,
};

pub const ADAPTIVE_THRESHOLD_NUM: usize = 95;
pub const ADAPTIVE_THRESHOLD_DEN: usize = 100;

/// Compresses `input` into a raw deflate stream owned by `allocator`.
pub fn compressDeflate(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer out_writer.deinit();

    // Ensure output writer buffer has > 8 bytes as asserted by flate.Compress.init.
    try out_writer.writer.ensureUnusedCapacity(64);

    const window_buf = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window_buf);

    var compressor = try flate.Compress.init(
        &out_writer.writer,
        window_buf,
        .raw,
        .default,
    );
    try compressor.writer.writeAll(input);
    try compressor.writer.flush();
    try compressor.finish();

    return out_writer.toOwnedSlice();
}

/// Decompresses a raw deflate stream into a newly allocated buffer bounded by `max_output_bytes`.
pub fn decompressDeflate(
    allocator: std.mem.Allocator,
    compressed: []const u8,
    max_output_bytes: usize,
) ![]u8 {
    var in_reader: std.Io.Reader = .fixed(compressed);
    const window_buf = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(window_buf);

    var decompressor = flate.Decompress.init(&in_reader, .raw, window_buf);

    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer out_writer.deinit();

    const written = try decompressor.reader.streamRemaining(&out_writer.writer);
    if (written > max_output_bytes) return error.DecompressedTooLarge;

    return out_writer.toOwnedSlice();
}

pub const AdaptivePageResult = struct {
    codec: PageCodec,
    /// Owned compressed bytes when `codec == .deflate`; `null` when `codec == .raw`
    /// (caller should encrypt the original `plaintext` slice directly).
    compressed_owned: ?[]u8,
};

/// Compresses a single logical page and keeps the deflate payload only if it shrinks
/// below 95% of the plaintext length (`< 95%`).
pub fn compressPageAdaptive(allocator: std.mem.Allocator, plaintext: []const u8) !AdaptivePageResult {
    if (plaintext.len < 64) {
        return .{ .codec = .raw, .compressed_owned = null };
    }
    const deflated = try compressDeflate(allocator, plaintext);
    if (deflated.len * ADAPTIVE_THRESHOLD_DEN < plaintext.len * ADAPTIVE_THRESHOLD_NUM) {
        return .{ .codec = .deflate, .compressed_owned = deflated };
    }
    allocator.free(deflated);
    return .{ .codec = .raw, .compressed_owned = null };
}
