const std = @import("std");
const Allocator = std.mem.Allocator;
const ir = @import("../rows/mod.zig");

pub const InconsistencyKind = enum {
    sample_outside_media_data,
    sample_eof_overflow,
    dimension_mismatch,
    sample_overlap,
    decompression_amplification,
};

pub const InconsistencyFact = struct {
    kind: InconsistencyKind,
    track_id: i64 = 0,
    run_id: i64 = 0,
    file_offset: u64 = 0,
    byte_length: u64 = 0,
    expected_a: u64 = 0,
    expected_b: u64 = 0,
    measured_a: u64 = 0,
    measured_b: u64 = 0,
};

/// Pure format-agnostic inconsistency detector returning typed facts:
/// - `sample_eof_overflow`: `SampleRun.end_offset > file_size`
/// - `sample_outside_media_data`: `SampleRun` not contained in any `media_data` region (`SampleRuns ⊆ media_data`)
/// - `dimension_mismatch`: `container_width/height != bitstream_width/height`
pub fn detectInconsistencies(
    allocator: Allocator,
    file_size: u64,
    regions: []const ir.IrRegionRow,
    configs: []const ir.IrCodecConfigRow,
    sample_runs: []const ir.IrSampleRunRow,
) ![]InconsistencyFact {
    var facts: std.ArrayList(InconsistencyFact) = .empty;
    errdefer facts.deinit(allocator);

    for (configs) |cfg| {
        const has_dim_mismatch = cfg.is_mismatch or
            (cfg.bitstream_width > 0 and cfg.container_width > 0 and
                (cfg.container_width != cfg.bitstream_width or cfg.container_height != cfg.bitstream_height));
        if (has_dim_mismatch) {
            try facts.append(allocator, .{
                .kind = .dimension_mismatch,
                .track_id = cfg.track_id,
                .expected_a = @intCast(@max(0, cfg.container_width)),
                .expected_b = @intCast(@max(0, cfg.container_height)),
                .measured_a = @intCast(@max(0, cfg.bitstream_width)),
                .measured_b = @intCast(@max(0, cfg.bitstream_height)),
            });
        }
    }

    if (sample_runs.len > 0) {
        const Interval = struct { start: u64, end: u64 };
        var media_intervals: std.ArrayList(Interval) = .empty;
        defer media_intervals.deinit(allocator);
        var media_data_bytes: u64 = 0;

        for (regions) |reg| {
            if (std.mem.eql(u8, reg.role, "media_data")) {
                media_data_bytes +|= reg.effective_end_offset -| reg.payload_offset;
                if (reg.effective_end_offset > reg.payload_offset) {
                    try media_intervals.append(allocator, .{
                        .start = reg.payload_offset,
                        .end = reg.effective_end_offset,
                    });
                }
            }
        }

        std.mem.sort(Interval, media_intervals.items, {}, struct {
            fn lessThan(_: void, a: Interval, b: Interval) bool {
                if (a.start != b.start) return a.start < b.start;
                return a.end < b.end;
            }
        }.lessThan);

        // Merge overlapping/adjacent media_data intervals for O(log R) containment lookup.
        var merged_len: usize = 0;
        for (media_intervals.items) |iv| {
            if (merged_len == 0 or iv.start > media_intervals.items[merged_len - 1].end) {
                media_intervals.items[merged_len] = iv;
                merged_len += 1;
            } else if (iv.end > media_intervals.items[merged_len - 1].end) {
                media_intervals.items[merged_len - 1].end = iv.end;
            }
        }
        const merged = media_intervals.items[0..merged_len];

        for (sample_runs) |sr| {
            if (sr.end_offset > file_size) {
                try facts.append(allocator, .{
                    .kind = .sample_eof_overflow,
                    .track_id = sr.track_id,
                    .run_id = sr.run_id,
                    .file_offset = sr.start_offset,
                    .byte_length = sr.byte_length,
                    .expected_a = file_size,
                    .measured_a = sr.end_offset,
                });
                continue;
            }

            // Binary search for the last interval with start <= sr.start_offset.
            var inside_media_data = false;
            var lo: usize = 0;
            var hi: usize = merged.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (merged[mid].start <= sr.start_offset) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if (lo > 0 and sr.end_offset <= merged[lo - 1].end) {
                inside_media_data = true;
            }
            if (!inside_media_data) {
                try facts.append(allocator, .{
                    .kind = .sample_outside_media_data,
                    .track_id = sr.track_id,
                    .run_id = sr.run_id,
                    .file_offset = sr.start_offset,
                    .byte_length = sr.byte_length,
                });
            }
        }

        // R10: Sweep-line sample run overlap & read amplification ratio
        const sorted = try allocator.dupe(ir.IrSampleRunRow, sample_runs);
        defer allocator.free(sorted);
        std.mem.sort(ir.IrSampleRunRow, sorted, {}, struct {
            fn lessThan(_: void, a: ir.IrSampleRunRow, b: ir.IrSampleRunRow) bool {
                if (a.start_offset != b.start_offset) return a.start_offset < b.start_offset;
                return a.end_offset < b.end_offset;
            }
        }.lessThan);

        var total_sample_bytes: u64 = sorted[0].byte_length;
        var max_end: u64 = sorted[0].end_offset;

        for (sorted[1..]) |sr| {
            total_sample_bytes +|= sr.byte_length;
            if (sr.start_offset < max_end) {
                try facts.append(allocator, .{
                    .kind = .sample_overlap,
                    .track_id = sr.track_id,
                    .run_id = sr.run_id,
                    .file_offset = sr.start_offset,
                    .byte_length = @min(sr.end_offset, max_end) - sr.start_offset,
                    .expected_a = max_end,
                    .measured_a = sr.start_offset,
                });
            }
            if (sr.end_offset > max_end) max_end = sr.end_offset;
        }

        if (media_data_bytes > 0 and total_sample_bytes > media_data_bytes) {
            try facts.append(allocator, .{
                .kind = .decompression_amplification,
                .expected_a = media_data_bytes,
                .measured_a = total_sample_bytes,
            });
        }
    }

    return try facts.toOwnedSlice(allocator);
}

test "detectInconsistencies flags sample outside media_data, EOF overflow, and dimension mismatch" {
    const regions = [_]ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "moov", .role = "metadata", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 100 },
        .{ .region_id = 1, .tag_name = "mdat", .role = "media_data", .header_offset = 100, .payload_offset = 108, .effective_end_offset = 200 },
    };
    const configs = [_]ir.IrCodecConfigRow{
        .{ .config_id = 1, .track_id = 1, .codec_tag = "avc1", .container_width = 1920, .container_height = 1080, .bitstream_width = 1280, .bitstream_height = 720, .is_mismatch = true },
    };
    const runs = [_]ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 20, .byte_length = 30, .end_offset = 50 }, // inside moov!
        .{ .run_id = 2, .track_id = 1, .start_offset = 180, .byte_length = 40, .end_offset = 220 }, // past EOF=200!
    };

    const facts = try detectInconsistencies(std.testing.allocator, 200, &regions, &configs, &runs);
    defer std.testing.allocator.free(facts);

    try std.testing.expectEqual(@as(usize, 3), facts.len);
    try std.testing.expectEqual(InconsistencyKind.dimension_mismatch, facts[0].kind);
    try std.testing.expectEqual(InconsistencyKind.sample_outside_media_data, facts[1].kind);
    try std.testing.expectEqual(InconsistencyKind.sample_eof_overflow, facts[2].kind);
}

test "detectInconsistencies flags R10 sample overlap and decompression amplification" {
    const regions = [_]ir.IrRegionRow{
        .{ .region_id = 0, .tag_name = "mdat", .role = "media_data", .header_offset = 0, .payload_offset = 8, .effective_end_offset = 108 },
    };
    const runs = [_]ir.IrSampleRunRow{
        .{ .run_id = 1, .track_id = 1, .start_offset = 8, .byte_length = 80, .end_offset = 88 },
        .{ .run_id = 2, .track_id = 1, .start_offset = 28, .byte_length = 80, .end_offset = 108 },
    };

    const facts = try detectInconsistencies(std.testing.allocator, 108, &regions, &.{}, &runs);
    defer std.testing.allocator.free(facts);

    try std.testing.expectEqual(@as(usize, 2), facts.len);
    try std.testing.expectEqual(InconsistencyKind.sample_overlap, facts[0].kind);
    try std.testing.expectEqual(InconsistencyKind.decompression_amplification, facts[1].kind);
    try std.testing.expectEqual(@as(u64, 160), facts[1].measured_a);
    try std.testing.expectEqual(@as(u64, 100), facts[1].expected_a);
}
