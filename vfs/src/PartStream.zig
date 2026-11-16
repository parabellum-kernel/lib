const std = @import("std");
const Crypto = @import("Crypto.zig");
const Compressor = @import("Compressor.zig");

/// Random-access encrypted `.part` codec and streaming reader (`GDRVPART` v1, `037` §5.3).
const PartStream = @This();

pub const INDEX_PAGE_INDEX: u64 = std.math.maxInt(u64);
pub const INDEX_ENTRY_SIZE: usize = 17; // u64 phys_offset + u32 phys_cipher_len + u32 uncompressed_len + u8 codec

pub const PageIndexEntry = struct {
    phys_offset: u64,
    phys_cipher_len: u32,
    uncompressed_len: u32,
    codec: Compressor.PageCodec,

    pub fn toBytes(self: PageIndexEntry) [INDEX_ENTRY_SIZE]u8 {
        var buf: [INDEX_ENTRY_SIZE]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.phys_offset, .little);
        std.mem.writeInt(u32, buf[8..12], self.phys_cipher_len, .little);
        std.mem.writeInt(u32, buf[12..16], self.uncompressed_len, .little);
        buf[16] = @intFromEnum(self.codec);
        return buf;
    }

    pub fn fromBytes(buf: *const [INDEX_ENTRY_SIZE]u8) !PageIndexEntry {
        const raw_codec = buf[16];
        const codec: Compressor.PageCodec = switch (raw_codec) {
            0x00 => .raw,
            0x01 => .deflate,
            else => return error.InvalidPageCodec,
        };
        return .{
            .phys_offset = std.mem.readInt(u64, buf[0..8], .little),
            .phys_cipher_len = std.mem.readInt(u32, buf[8..12], .little),
            .uncompressed_len = std.mem.readInt(u32, buf[12..16], .little),
            .codec = codec,
        };
    }
};

pub const ByteRangeReader = struct {
    ptr: *anyopaque,
    readRangeFn: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) anyerror![]u8,

    pub fn readRange(self: ByteRangeReader, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) ![]u8 {
        return self.readRangeFn(self.ptr, allocator, start, end_inclusive);
    }
};

/// Encodes `plaintext` into a complete `GDRVPART` v1 blob (64-byte header + optional encrypted page index + AEAD pages).
pub fn encodePart(
    allocator: std.mem.Allocator,
    io: std.Io,
    file_dek: [Crypto.KEY_LEN]u8,
    inode_ulid: [16]u8,
    part_index: u32,
    plaintext: []const u8,
    adaptive: bool,
) ![]u8 {
    const page_size = Crypto.PAGE_SIZE_BYTES;
    const page_count: u32 = if (plaintext.len == 0) 0 else @intCast((plaintext.len + page_size - 1) / page_size);
    const part_key = Crypto.derivePartKey(file_dek, inode_ulid, part_index);

    var nonce_prefix: [16]u8 = undefined;
    io.random(&nonce_prefix);

    const index_plain_len: usize = @as(usize, page_count) * INDEX_ENTRY_SIZE;
    const index_cipher_len: u32 = if (adaptive) @intCast(index_plain_len + Crypto.TAG_LEN) else 0;
    const data_start: u64 = Crypto.GDRVPART_HEADER_LEN + index_cipher_len;

    var entries = try allocator.alloc(PageIndexEntry, page_count);
    defer allocator.free(entries);

    var sealed_pages = try allocator.alloc([]u8, page_count);
    var built_pages: usize = 0;
    defer {
        for (sealed_pages[0..built_pages]) |p| allocator.free(p);
        allocator.free(sealed_pages);
    }

    var cursor: u64 = data_start;
    for (0..page_count) |p_idx| {
        const start = p_idx * page_size;
        const end = @min(start + page_size, plaintext.len);
        const slice = plaintext[start..end];
        const is_last = (p_idx + 1 == page_count);

        var codec: Compressor.PageCodec = .raw;
        var owned_comp: ?[]u8 = null;
        defer if (owned_comp) |c| allocator.free(c);

        if (adaptive) {
            const res = try Compressor.compressPageAdaptive(allocator, slice);
            codec = res.codec;
            owned_comp = res.compressed_owned;
        }

        const payload = if (owned_comp) |c| c else slice;
        const sealed = try allocator.alloc(u8, payload.len + Crypto.TAG_LEN);
        errdefer allocator.free(sealed);

        Crypto.encryptPage(
            part_key,
            inode_ulid,
            part_index,
            @intCast(p_idx),
            is_last,
            nonce_prefix,
            payload,
            sealed,
        );

        sealed_pages[built_pages] = sealed;
        built_pages += 1;

        entries[p_idx] = .{
            .phys_offset = cursor,
            .phys_cipher_len = @intCast(sealed.len),
            .uncompressed_len = @intCast(slice.len),
            .codec = codec,
        };
        cursor += sealed.len;
    }

    const total_len: usize = @intCast(cursor);
    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    const hdr = Crypto.GdrvPartHeader{
        .flags = .{ .per_page_adaptive = adaptive },
        .page_count = page_count,
        .nonce_prefix = nonce_prefix,
        .index_offset = if (adaptive) Crypto.GDRVPART_HEADER_LEN else 0,
        .index_cipher_len = index_cipher_len,
    };
    const hdr_bytes = hdr.toBytes();
    @memcpy(out[0..Crypto.GDRVPART_HEADER_LEN], &hdr_bytes);

    if (adaptive) {
        const idx_plain = try allocator.alloc(u8, index_plain_len);
        defer allocator.free(idx_plain);
        for (entries, 0..) |entry, i| {
            const eb = entry.toBytes();
            @memcpy(idx_plain[i * INDEX_ENTRY_SIZE ..][0..INDEX_ENTRY_SIZE], &eb);
        }
        Crypto.encryptPage(
            part_key,
            inode_ulid,
            part_index,
            INDEX_PAGE_INDEX,
            true,
            nonce_prefix,
            idx_plain,
            out[Crypto.GDRVPART_HEADER_LEN..][0..index_cipher_len],
        );
    }

    var write_pos: usize = @intCast(data_start);
    for (sealed_pages[0..built_pages]) |sp| {
        @memcpy(out[write_pos..][0..sp.len], sp);
        write_pos += sp.len;
    }

    return out;
}

/// Random-access reader for a single encrypted `GDRVPART` v1 blob.
pub const Reader = struct {
    allocator: std.mem.Allocator,
    source: ByteRangeReader,
    part_key: [Crypto.KEY_LEN]u8,
    inode_ulid: [16]u8,
    part_index: u32,
    logical_len: u64,
    header: Crypto.GdrvPartHeader,
    index_entries: ?[]PageIndexEntry,

    pub fn open(
        allocator: std.mem.Allocator,
        source: ByteRangeReader,
        file_dek: [Crypto.KEY_LEN]u8,
        inode_ulid: [16]u8,
        part_index: u32,
        logical_len: u64,
    ) !Reader {
        const hdr_raw = try source.readRange(allocator, 0, Crypto.GDRVPART_HEADER_LEN - 1);
        defer allocator.free(hdr_raw);
        if (hdr_raw.len != Crypto.GDRVPART_HEADER_LEN) return error.InvalidPartHeader;

        const hdr = try Crypto.GdrvPartHeader.fromBytes(hdr_raw[0..Crypto.GDRVPART_HEADER_LEN]);
        const part_key = Crypto.derivePartKey(file_dek, inode_ulid, part_index);

        var entries: ?[]PageIndexEntry = null;
        if (hdr.flags.per_page_adaptive) {
            if (hdr.index_cipher_len < Crypto.TAG_LEN) return error.InvalidPartIndex;
            const idx_sealed = try source.readRange(
                allocator,
                hdr.index_offset,
                hdr.index_offset + hdr.index_cipher_len - 1,
            );
            defer allocator.free(idx_sealed);

            const idx_plain = try allocator.alloc(u8, idx_sealed.len - Crypto.TAG_LEN);
            defer allocator.free(idx_plain);

            try Crypto.decryptPage(
                part_key,
                inode_ulid,
                part_index,
                INDEX_PAGE_INDEX,
                true,
                hdr.nonce_prefix,
                idx_sealed,
                idx_plain,
            );

            if (idx_plain.len != @as(usize, hdr.page_count) * INDEX_ENTRY_SIZE) {
                return error.InvalidPartIndex;
            }
            const parsed = try allocator.alloc(PageIndexEntry, hdr.page_count);
            errdefer allocator.free(parsed);
            for (0..hdr.page_count) |i| {
                const slice = idx_plain[i * INDEX_ENTRY_SIZE ..][0..INDEX_ENTRY_SIZE];
                parsed[i] = try PageIndexEntry.fromBytes(slice);
            }
            entries = parsed;
        }

        return .{
            .allocator = allocator,
            .source = source,
            .part_key = part_key,
            .inode_ulid = inode_ulid,
            .part_index = part_index,
            .logical_len = logical_len,
            .header = hdr,
            .index_entries = entries,
        };
    }

    pub fn deinit(self: *Reader) void {
        if (self.index_entries) |e| self.allocator.free(e);
    }

    /// Reads `[offset .. offset + out.len)` plaintext bytes, fetching only the intersecting encrypted pages.
    pub fn readAt(self: *const Reader, offset: u64, out: []u8) !usize {
        if (offset >= self.logical_len or out.len == 0) return 0;

        const to_read: usize = @intCast(@min(@as(u64, out.len), self.logical_len - offset));
        const page_size: u64 = self.header.page_size;
        const first_page: usize = @intCast(offset / page_size);
        const last_page: usize = @intCast((offset + to_read - 1) / page_size);

        var out_pos: usize = 0;
        for (first_page..last_page + 1) |p_idx| {
            const page_logical_start: u64 = @as(u64, p_idx) * page_size;
            const page_logical_len: usize = if (self.index_entries) |entries|
                entries[p_idx].uncompressed_len
            else
                @intCast(@min(page_size, self.logical_len - page_logical_start));

            const phys_start: u64 = if (self.index_entries) |entries|
                entries[p_idx].phys_offset
            else
                Crypto.GDRVPART_HEADER_LEN + @as(u64, p_idx) * (page_size + Crypto.TAG_LEN);

            const phys_len: usize = if (self.index_entries) |entries|
                entries[p_idx].phys_cipher_len
            else
                page_logical_len + Crypto.TAG_LEN;

            const sealed = try self.source.readRange(self.allocator, phys_start, phys_start + phys_len - 1);
            defer self.allocator.free(sealed);

            const dec_buf = try self.allocator.alloc(u8, sealed.len - Crypto.TAG_LEN);
            defer self.allocator.free(dec_buf);

            const is_last = (p_idx + 1 == self.header.page_count);
            try Crypto.decryptPage(
                self.part_key,
                self.inode_ulid,
                self.part_index,
                @intCast(p_idx),
                is_last,
                self.header.nonce_prefix,
                sealed,
                dec_buf,
            );

            var owned_plain: ?[]u8 = null;
            defer if (owned_plain) |p| self.allocator.free(p);

            const page_plain: []const u8 = blk: {
                if (self.index_entries) |entries| {
                    if (entries[p_idx].codec == .deflate) {
                        const p = try Compressor.decompressDeflate(self.allocator, dec_buf, page_logical_len);
                        owned_plain = p;
                        break :blk p;
                    }
                }
                break :blk dec_buf;
            };

            const copy_start: usize = if (p_idx == first_page) @intCast(offset - page_logical_start) else 0;
            const avail_in_page = page_plain.len - copy_start;
            const copy_len = @min(avail_in_page, to_read - out_pos);
            @memcpy(out[out_pos..][0..copy_len], page_plain[copy_start..][0..copy_len]);
            out_pos += copy_len;
        }

        return out_pos;
    }
};

/// In-memory LRU cache for encrypted byte ranges (headers, page indices, and 256 KiB AEAD pages).
/// Keyed by `(file_id, start, end_inclusive)` so repeated reads or seeks avoid redundant HTTP Range calls.
pub const RangeCache = struct {
    const Entry = struct {
        data: []u8,
        last_access: u64,
    };

    allocator: std.mem.Allocator,
    max_bytes: usize,
    current_bytes: usize = 0,
    tick: u64 = 0,
    entries: std.StringHashMapUnmanaged(Entry) = .empty,
    hits: u64 = 0,
    misses: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_bytes: usize) RangeCache {
        return .{
            .allocator = allocator,
            .max_bytes = max_bytes,
        };
    }

    pub fn deinit(self: *RangeCache) void {
        var it = self.entries.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.free(e.value_ptr.data);
        }
        self.entries.deinit(self.allocator);
        self.current_bytes = 0;
    }

    fn makeKey(allocator: std.mem.Allocator, file_id: []const u8, start: u64, end_inclusive: u64) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}:{d}:{d}", .{ file_id, start, end_inclusive });
    }

    pub fn get(self: *RangeCache, allocator: std.mem.Allocator, file_id: []const u8, start: u64, end_inclusive: u64) !?[]u8 {
        if (self.max_bytes == 0) return null;
        const key = try makeKey(allocator, file_id, start, end_inclusive);
        defer allocator.free(key);

        if (self.entries.getPtr(key)) |entry| {
            self.tick += 1;
            entry.last_access = self.tick;
            self.hits += 1;
            return try allocator.dupe(u8, entry.data);
        }
        return null;
    }

    pub fn put(self: *RangeCache, file_id: []const u8, start: u64, end_inclusive: u64, data: []const u8) !void {
        if (self.max_bytes == 0 or data.len > self.max_bytes) return;
        const key = try makeKey(self.allocator, file_id, start, end_inclusive);
        errdefer self.allocator.free(key);

        if (self.entries.getPtr(key)) |existing| {
            self.allocator.free(key);
            self.tick += 1;
            existing.last_access = self.tick;
            return;
        }

        while (self.current_bytes + data.len > self.max_bytes and self.entries.count() > 0) {
            self.evictOneLru();
        }

        const owned_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(owned_data);
        self.tick += 1;
        try self.entries.put(self.allocator, key, .{
            .data = owned_data,
            .last_access = self.tick,
        });
        self.current_bytes += owned_data.len;
    }

    fn evictOneLru(self: *RangeCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_tick: u64 = std.math.maxInt(u64);
        var it = self.entries.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.last_access < oldest_tick) {
                oldest_tick = e.value_ptr.last_access;
                oldest_key = e.key_ptr.*;
            }
        }
        if (oldest_key) |k| {
            if (self.entries.fetchRemove(k)) |kv| {
                self.current_bytes -= kv.value.data.len;
                self.allocator.free(kv.key);
                self.allocator.free(kv.value.data);
            }
        }
    }
};

/// `ByteRangeReader` wrapper that serves hits from `RangeCache` and populates it on misses.
pub const CachedRangeReader = struct {
    inner: ByteRangeReader,
    cache: *RangeCache,
    file_id: []const u8,
    base_offset: u64 = 0,

    fn readRange(ptr: *anyopaque, allocator: std.mem.Allocator, start: u64, end_inclusive: u64) anyerror![]u8 {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        const abs_start = self.base_offset + start;
        const abs_end = self.base_offset + end_inclusive;
        if (try self.cache.get(allocator, self.file_id, abs_start, abs_end)) |hit| {
            return hit;
        }
        self.cache.misses += 1;
        const fresh = try self.inner.readRange(allocator, start, end_inclusive);
        errdefer allocator.free(fresh);
        try self.cache.put(self.file_id, abs_start, abs_end, fresh);
        return fresh;
    }

    pub fn byteReader(self: *CachedRangeReader) ByteRangeReader {
        return .{ .ptr = self, .readRangeFn = readRange };
    }
};

