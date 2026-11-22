const std = @import("std");
const Crypto = @import("Crypto.zig");
const PartStream = @import("PartStream.zig");
const CatalogPort = @import("CatalogPort.zig");
const PoolAllocator = @import("PoolAllocator.zig");

pub const PackConfig = struct {
    auto_pack_enabled: bool = false,
    small_file_threshold_bytes: u64 = 8 * 1024 * 1024,
    max_pack_size_bytes: u64 = 64 * 1024 * 1024,
    max_coalesce_gap_bytes: u64 = 256 * 1024,
    pack_readahead_bytes: u64 = 2 * 1024 * 1024,
    upload_policy: ?PoolAllocator.UploadPolicy = null,
};

pub const ReadSpan = struct {
    offset: u64,
    len: u64,

    pub fn end(self: ReadSpan) u64 {
        return self.offset + self.len;
    }
};

pub const SmallFileInput = struct {
    parent_id: ?[]const u8 = null,
    partition_id: []const u8 = "default",
    share_scope: []const u8 = "private",
    name: []const u8,
    inode_id: []const u8,
    inode_ulid: [16]u8,
    plaintext: []const u8,
    mime_type: ?[]const u8 = null,
    adaptive_compression: bool = true,
};

pub const PackItem = struct {
    parent_id: ?[]const u8,
    name: []const u8,
    inode_id: []const u8,
    logical_size: u64,
    phys_part_offset: u64,
    phys_part_len: u64,
    wrapped_dek: [Crypto.WRAPPED_KEY_WITH_NONCE_LEN]u8,
    content_sha256: [32]u8,
    compression_mode: []const u8,
    mime_type: ?[]const u8,
};

pub const PackBatch = struct {
    blob: []u8,
    items: []PackItem,

    pub fn deinit(self: *PackBatch, allocator: std.mem.Allocator) void {
        allocator.free(self.blob);
        allocator.free(self.items);
    }
};

/// Encodes and packs `inputs` into one or more `.pack` blobs bounded by `config.max_pack_size_bytes`.
/// Each file retains its own random `file_dek` and independent `GDRVPART` v1 header/AEAD.
pub fn buildPacks(
    allocator: std.mem.Allocator,
    io: std.Io,
    vmk: [Crypto.KEY_LEN]u8,
    inputs: []const SmallFileInput,
    config: PackConfig,
) ![]PackBatch {
    var batches = std.ArrayListUnmanaged(PackBatch).empty;
    errdefer {
        for (batches.items) |*b| b.deinit(allocator);
        batches.deinit(allocator);
    }

    if (inputs.len == 0) return batches.toOwnedSlice(allocator);

    var cur_blob = std.ArrayListUnmanaged(u8).empty;
    errdefer cur_blob.deinit(allocator);
    var cur_items = std.ArrayListUnmanaged(PackItem).empty;
    errdefer cur_items.deinit(allocator);

    var cur_partition: []const u8 = inputs[0].partition_id;
    var cur_scope: []const u8 = inputs[0].share_scope;

    for (inputs) |inp| {
        const scope_changed = !std.mem.eql(u8, inp.partition_id, cur_partition) or
            !std.mem.eql(u8, inp.share_scope, cur_scope);
        if (scope_changed and cur_items.items.len > 0) {
            try batches.append(allocator, .{
                .blob = try cur_blob.toOwnedSlice(allocator),
                .items = try cur_items.toOwnedSlice(allocator),
            });
            cur_partition = inp.partition_id;
            cur_scope = inp.share_scope;
        }

        var file_dek: [Crypto.KEY_LEN]u8 = undefined;
        io.random(&file_dek);
        const wrapped_dek = Crypto.wrapKeyWithNonce(io, vmk, file_dek, &inp.inode_ulid);

        var sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(inp.plaintext, &sha256, .{});

        const encoded = try PartStream.encodePart(
            allocator,
            io,
            file_dek,
            inp.inode_ulid,
            0,
            inp.plaintext,
            inp.adaptive_compression,
        );
        defer allocator.free(encoded);

        if (cur_items.items.len > 0 and cur_blob.items.len + encoded.len > config.max_pack_size_bytes) {
            try batches.append(allocator, .{
                .blob = try cur_blob.toOwnedSlice(allocator),
                .items = try cur_items.toOwnedSlice(allocator),
            });
        }

        const off: u64 = cur_blob.items.len;
        try cur_blob.appendSlice(allocator, encoded);
        try cur_items.append(allocator, .{
            .parent_id = inp.parent_id,
            .name = inp.name,
            .inode_id = inp.inode_id,
            .logical_size = inp.plaintext.len,
            .phys_part_offset = off,
            .phys_part_len = encoded.len,
            .wrapped_dek = wrapped_dek,
            .content_sha256 = sha256,
            .compression_mode = if (inp.adaptive_compression) "per_page_adaptive" else "none",
            .mime_type = inp.mime_type,
        });
    }

    if (cur_items.items.len > 0) {
        try batches.append(allocator, .{
            .blob = try cur_blob.toOwnedSlice(allocator),
            .items = try cur_items.toOwnedSlice(allocator),
        });
    }

    return batches.toOwnedSlice(allocator);
}

/// Extracts the `GDRVPART` v1 slice for a single packed item from a full pack buffer.
pub fn extractEntrySlice(pack_bytes: []const u8, phys_part_offset: u64, phys_part_len: u64) ![]const u8 {
    if (phys_part_offset > pack_bytes.len) return error.InvalidPackOffset;
    const end = std.math.add(u64, phys_part_offset, phys_part_len) catch return error.InvalidPackOffset;
    if (end > pack_bytes.len) return error.InvalidPackOffset;
    return pack_bytes[@intCast(phys_part_offset)..@intCast(end)];
}

/// Builds sorted, coalesced `ReadSpan`s for a set of extents sharing the same `gdrive_file_id`.
pub fn spansForExtents(
    allocator: std.mem.Allocator,
    extents: []const CatalogPort.InodeExtent,
    max_coalesce_gap_bytes: u64,
) ![]ReadSpan {
    const raw = try allocator.alloc(ReadSpan, extents.len);
    defer allocator.free(raw);

    for (extents, 0..) |ext, i| {
        const len = if (ext.phys_part_len > 0) ext.phys_part_len else ext.physical_size;
        raw[i] = .{ .offset = ext.phys_part_offset, .len = len };
    }

    std.mem.sort(ReadSpan, raw, {}, struct {
        fn lessThan(_: void, a: ReadSpan, b: ReadSpan) bool {
            return a.offset < b.offset;
        }
    }.lessThan);

    return coalesceSpans(allocator, raw, max_coalesce_gap_bytes);
}

/// Adapts a `PartStream.ByteRangeReader` to read a `GDRVPART` embedded at `base_offset` inside a `.pack` blob.
pub const OffsetRangeReader = struct {
    inner: PartStream.ByteRangeReader,
    base_offset: u64,

    fn readRange(ptr: *anyopaque, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) anyerror![]u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return self.inner.readRange(allocator, self.base_offset + start, self.base_offset + end_inclusive);
    }

    pub fn byteReader(self: *OffsetRangeReader) PartStream.ByteRangeReader {
        return .{ .ptr = self, .readRangeFn = readRange };
    }
};

/// Adapts an in-memory buffer (e.g. a downloaded coalesced pack span) as a `PartStream.ByteRangeReader`.
pub const SliceRangeReader = struct {
    data: []const u8,
    base_offset: u64 = 0,

    fn readRange(ptr: *anyopaque, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) anyerror![]u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        if (start < self.base_offset) return error.RangeOutOfBounds;
        const rel_start = start - self.base_offset;
        const rel_end = (end_inclusive - self.base_offset) + 1;
        if (rel_end > self.data.len or rel_start > rel_end) return error.RangeOutOfBounds;
        return allocator.dupe(u8, self.data[rel_start..rel_end]);
    }

    pub fn byteReader(self: *SliceRangeReader) PartStream.ByteRangeReader {
        return .{ .ptr = self, .readRangeFn = readRange };
    }
};

/// Coalesces sorted `ReadSpan`s targeting the same `gdrive_file_id` when the gap between
/// consecutive spans is `<= max_coalesce_gap_bytes` (ARCH-037A Section 3).
pub fn coalesceSpans(
    allocator: std.mem.Allocator,
    sorted_spans: []const ReadSpan,
    max_coalesce_gap_bytes: u64,
) ![]ReadSpan {
    var out = std.ArrayListUnmanaged(ReadSpan).empty;
    errdefer out.deinit(allocator);
    for (sorted_spans) |span| {
        if (out.items.len == 0) {
            try out.append(allocator, span);
            continue;
        }
        const prev = &out.items[out.items.len - 1];
        if (span.offset <= prev.end() +| max_coalesce_gap_bytes) {
            const new_end = @max(prev.end(), span.end());
            prev.len = new_end - prev.offset;
        } else {
            try out.append(allocator, span);
        }
    }
    return out.toOwnedSlice(allocator);
}
