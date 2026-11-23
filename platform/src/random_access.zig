const std = @import("std");
const builtin = @import("builtin");

/// Platform-agnostic random-access read-only file handle (VTable pattern).
/// Implementations must support concurrent `readAt` calls at arbitrary offsets.
pub const RandomAccessFile = struct {
    ptr: ?*anyopaque = null,
    vtable: *const VTable,

    pub const VTable = struct {
        size: *const fn (ctx: ?*anyopaque) u64,
        read_at: *const fn (ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!void,
        close: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator) void,
    };

    pub fn size(self: RandomAccessFile) u64 {
        return self.vtable.size(self.ptr);
    }

    pub fn readAt(self: RandomAccessFile, offset: u64, dest: []u8) anyerror!void {
        return self.vtable.read_at(self.ptr, offset, dest);
    }

    pub fn close(self: RandomAccessFile, alloc: std.mem.Allocator) void {
        self.vtable.close(self.ptr, alloc);
    }
};

/// Opens an existing file at `path` for thread-safe random-access reading.
pub fn openReadOnly(alloc: std.mem.Allocator, path: []const u8) !RandomAccessFile {
    return switch (builtin.os.tag) {
        .windows => try WindowsRandomAccessFile.open(alloc, path),
        else => try PosixRandomAccessFile.open(alloc, path),
    };
}

const PosixRandomAccessFile = struct {
    fd: std.posix.fd_t,
    file_size: u64,

    const c_posix = struct {
        extern "c" fn pread(fd: c_int, buf: [*]u8, count: usize, offset: i64) isize;
        extern "c" fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
    };

    fn open(alloc: std.mem.Allocator, path: []const u8) !RandomAccessFile {
        const path_z = try alloc.dupeSentinel(u8, path, 0);
        defer alloc.free(path_z);

        const fd = std.c.open(path_z.ptr, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
        if (fd < 0) return error.FileNotFound;
        errdefer _ = std.c.close(fd);

        const end_off = c_posix.lseek(fd, 0, 2);
        if (end_off < 0) return error.IoError;
        const fsize: u64 = @intCast(end_off);

        const self = try alloc.create(PosixRandomAccessFile);
        self.* = .{
            .fd = fd,
            .file_size = fsize,
        };
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn sizeFn(ctx: ?*anyopaque) u64 {
        const self: *const PosixRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        return self.file_size;
    }

    fn readAtFn(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!void {
        if (dest.len == 0) return;
        const self: *const PosixRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        const end = std.math.add(u64, offset, dest.len) catch return error.OutOfBounds;
        if (end > self.file_size) return error.OutOfBounds;

        var total: usize = 0;
        while (total < dest.len) {
            const off_i64: i64 = @intCast(offset + total);
            const rc = c_posix.pread(self.fd, dest.ptr + total, dest.len - total, off_i64);
            if (rc < 0) {
                const err = std.c._errno().*;
                if (err == @intFromEnum(std.posix.E.INTR)) continue;
                return error.IoError;
            }
            if (rc == 0) return error.UnexpectedEof;
            total += @intCast(rc);
        }
    }

    fn closeFn(ctx: ?*anyopaque, alloc: std.mem.Allocator) void {
        const self: *PosixRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        _ = std.c.close(self.fd);
        alloc.destroy(self);
    }

    const vtable = RandomAccessFile.VTable{
        .size = sizeFn,
        .read_at = readAtFn,
        .close = closeFn,
    };
};

const WindowsRandomAccessFile = struct {
    fp: *std.c.FILE,
    file_size: u64,
    locked: std.atomic.Value(bool) = .init(false),

    fn lock(self: *WindowsRandomAccessFile) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch {};
        }
    }

    fn unlock(self: *WindowsRandomAccessFile) void {
        self.locked.store(false, .release);
    }

    const c_win = struct {
        extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*std.c.FILE;
        extern "c" fn fclose(stream: *std.c.FILE) c_int;
        extern "c" fn _fseeki64(stream: *std.c.FILE, offset: i64, origin: c_int) c_int;
        extern "c" fn _ftelli64(stream: *std.c.FILE) i64;
        extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: *std.c.FILE) usize;
    };

    fn open(alloc: std.mem.Allocator, path: []const u8) !RandomAccessFile {
        const path_z = try alloc.dupeSentinel(u8, path, 0);
        defer alloc.free(path_z);

        const fp = c_win.fopen(path_z.ptr, "rb") orelse return error.FileNotFound;
        errdefer _ = c_win.fclose(fp);

        if (c_win._fseeki64(fp, 0, 2) != 0) return error.IoError;
        const pos = c_win._ftelli64(fp);
        if (pos < 0) return error.IoError;

        const self = try alloc.create(WindowsRandomAccessFile);
        self.* = .{
            .fp = fp,
            .file_size = @intCast(pos),
        };
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn sizeFn(ctx: ?*anyopaque) u64 {
        const self: *const WindowsRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        return self.file_size;
    }

    fn readAtFn(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!void {
        if (dest.len == 0) return;
        const self: *WindowsRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        const end = std.math.add(u64, offset, dest.len) catch return error.OutOfBounds;
        if (end > self.file_size) return error.OutOfBounds;

        self.lock();
        defer self.unlock();

        if (c_win._fseeki64(self.fp, @intCast(offset), 0) != 0) return error.IoError;
        var total: usize = 0;
        while (total < dest.len) {
            const n = c_win.fread(dest.ptr + total, 1, dest.len - total, self.fp);
            if (n == 0) return error.UnexpectedEof;
            total += n;
        }
    }

    fn closeFn(ctx: ?*anyopaque, alloc: std.mem.Allocator) void {
        const self: *WindowsRandomAccessFile = @ptrCast(@alignCast(ctx.?));
        _ = c_win.fclose(self.fp);
        alloc.destroy(self);
    }

    const vtable = RandomAccessFile.VTable{
        .size = sizeFn,
        .read_at = readAtFn,
        .close = closeFn,
    };
};

test "RandomAccessFile reads arbitrary offsets without reopening" {
    const alloc = std.testing.allocator;
    const tmp_path = "/tmp/parabellum_platform_raf_test.bin";
    {
        const path_z = try alloc.dupeSentinel(u8, tmp_path, 0);
        defer alloc.free(path_z);
        const fp = std.c.fopen(path_z.ptr, "wb") orelse return error.IoError;
        defer _ = std.c.fclose(fp);
        const data = "0123456789ABCDEF";
        _ = std.c.fwrite(data.ptr, 1, data.len, fp);
    }
    defer {
        const path_z = alloc.dupeSentinel(u8, tmp_path, 0) catch unreachable;
        defer alloc.free(path_z);
        _ = std.c.unlink(path_z.ptr);
    }

    const raf = try openReadOnly(alloc, tmp_path);
    defer raf.close(alloc);

    try std.testing.expectEqual(@as(u64, 16), raf.size());
    var buf: [4]u8 = undefined;
    try raf.readAt(10, &buf);
    try std.testing.expectEqualSlices(u8, "ABCD", &buf);
    try raf.readAt(0, &buf);
    try std.testing.expectEqualSlices(u8, "0123", &buf);
    try std.testing.expectError(error.OutOfBounds, raf.readAt(14, &buf));
}
