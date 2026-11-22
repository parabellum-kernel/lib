const std = @import("std");

pub const CodecError = error{
    UnexpectedEof,
    InvalidTag,
    LengthOverflow,
    TrailingBytes,
    OutOfMemory,
};

/// Strict canonical little-endian binary writer backed by `std.ArrayList(u8)`.
pub const BinaryWriter = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) BinaryWriter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BinaryWriter) void {
        self.buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn toOwnedSlice(self: *BinaryWriter) CodecError![]u8 {
        return self.buf.toOwnedSlice(self.allocator) catch return error.OutOfMemory;
    }

    pub fn writeU8(self: *BinaryWriter, val: u8) CodecError!void {
        self.buf.append(self.allocator, val) catch return error.OutOfMemory;
    }

    pub fn writeBool(self: *BinaryWriter, val: bool) CodecError!void {
        try self.writeU8(@intFromBool(val));
    }

    pub fn writeBytes(self: *BinaryWriter, data: []const u8) CodecError!void {
        self.buf.appendSlice(self.allocator, data) catch return error.OutOfMemory;
    }

    pub fn writeInt(self: *BinaryWriter, comptime T: type, val: T) CodecError!void {
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, val, .little);
        try self.writeBytes(&bytes);
    }

    pub fn writeSlice(self: *BinaryWriter, data: []const u8) CodecError!void {
        const len = std.math.cast(u32, data.len) orelse return error.LengthOverflow;
        try self.writeInt(u32, len);
        try self.writeBytes(data);
    }

    pub fn writeOptSlice(self: *BinaryWriter, data: ?[]const u8) CodecError!void {
        if (data) |d| {
            try self.writeU8(1);
            try self.writeSlice(d);
        } else {
            try self.writeU8(0);
        }
    }

    /// Writes a canonical domain-separation label (UTF-8 bytes plus trailing NUL byte).
    pub fn writeDomainLabel(self: *BinaryWriter, label: []const u8) CodecError!void {
        try self.writeBytes(label);
        try self.writeU8(0);
    }
};

/// Strict bounds-checked little-endian binary reader for untrusted payloads.
pub const BinaryReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) BinaryReader {
        return .{ .data = data, .pos = 0 };
    }

    pub fn remaining(self: *const BinaryReader) usize {
        return self.data.len - self.pos;
    }

    pub fn expectEof(self: *const BinaryReader) CodecError!void {
        if (self.pos != self.data.len) return error.TrailingBytes;
    }

    pub fn readU8(self: *BinaryReader) CodecError!u8 {
        if (self.pos >= self.data.len) return error.UnexpectedEof;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    pub fn readBool(self: *BinaryReader) CodecError!bool {
        return switch (try self.readU8()) {
            0 => false,
            1 => true,
            else => error.InvalidTag,
        };
    }

    pub fn readBytes(self: *BinaryReader, comptime n: usize) CodecError![n]u8 {
        if (self.remaining() < n) return error.UnexpectedEof;
        var out: [n]u8 = undefined;
        @memcpy(&out, self.data[self.pos .. self.pos + n]);
        self.pos += n;
        return out;
    }

    pub fn readInt(self: *BinaryReader, comptime T: type) CodecError!T {
        const bytes = try self.readBytes(@sizeOf(T));
        return std.mem.readInt(T, &bytes, .little);
    }

    pub fn readEnum(self: *BinaryReader, comptime E: type) CodecError!E {
        const Tag = @typeInfo(E).@"enum".tag_type;
        const raw: Tag = if (@bitSizeOf(Tag) <= 8) blk: {
            const b = try self.readU8();
            break :blk std.math.cast(Tag, b) orelse return error.InvalidTag;
        } else try self.readInt(Tag);
        return std.enums.fromInt(E, raw) orelse error.InvalidTag;
    }

    pub fn readSlice(self: *BinaryReader, allocator: std.mem.Allocator) CodecError![]u8 {
        const len_u32 = try self.readInt(u32);
        const len = std.math.cast(usize, len_u32) orelse return error.LengthOverflow;
        if (self.remaining() < len) return error.UnexpectedEof;
        const out = allocator.dupe(u8, self.data[self.pos .. self.pos + len]) catch return error.OutOfMemory;
        self.pos += len;
        return out;
    }

    pub fn readOptSlice(self: *BinaryReader, allocator: std.mem.Allocator) CodecError!?[]u8 {
        return switch (try self.readU8()) {
            0 => null,
            1 => try self.readSlice(allocator),
            else => error.InvalidTag,
        };
    }
};

test "BinaryWriter and BinaryReader round-trip and reject malformed inputs" {
    const alloc = std.testing.allocator;
    const TestEnum = enum(u8) { alpha = 0, beta = 1 };

    var w = BinaryWriter.init(alloc);
    defer w.deinit();

    try w.writeDomainLabel("parabellum/test/v1");
    try w.writeInt(u64, 0x0102030405060708);
    try w.writeBool(true);
    try w.writeU8(@intFromEnum(TestEnum.beta));
    try w.writeSlice("hello");
    try w.writeOptSlice(null);
    try w.writeOptSlice("world");

    const encoded = try w.toOwnedSlice();
    defer alloc.free(encoded);

    var r = BinaryReader.init(encoded);
    const label = try r.readBytes("parabellum/test/v1".len + 1);
    try std.testing.expectEqualSlices(u8, "parabellum/test/v1\x00", &label);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), try r.readInt(u64));
    try std.testing.expectEqual(true, try r.readBool());
    try std.testing.expectEqual(TestEnum.beta, try r.readEnum(TestEnum));

    const s1 = try r.readSlice(alloc);
    defer alloc.free(s1);
    try std.testing.expectEqualSlices(u8, "hello", s1);

    try std.testing.expect((try r.readOptSlice(alloc)) == null);

    const s2 = (try r.readOptSlice(alloc)).?;
    defer alloc.free(s2);
    try std.testing.expectEqualSlices(u8, "world", s2);

    try r.expectEof();

    // Invalid enum tag
    var bad_enum = BinaryReader.init(&[_]u8{99});
    try std.testing.expectError(error.InvalidTag, bad_enum.readEnum(TestEnum));

    // Truncated length-prefixed slice
    var bad_len = BinaryReader.init(&[_]u8{ 10, 0, 0, 0, 'a', 'b' });
    try std.testing.expectError(error.UnexpectedEof, bad_len.readSlice(alloc));

    // Trailing bytes
    var trailing = BinaryReader.init(&[_]u8{ 0, 1 });
    _ = try trailing.readBool();
    try std.testing.expectError(error.TrailingBytes, trailing.expectEof());
}
