const std = @import("std");
const fs = @import("fs.zig");

const c = struct {
    pub extern "c" fn _fullpath(abs_path: ?[*]u8, rel_path: [*:0]const u8, max_len: usize) ?[*:0]u8;
    pub extern "c" fn _access(path: [*:0]const u8, mode: c_int) c_int;
    pub extern "c" fn _mkdir(path: [*:0]const u8) c_int;
    pub extern "c" fn _rmdir(path: [*:0]const u8) c_int;
    pub extern "c" fn _unlink(path: [*:0]const u8) c_int;
    pub extern "c" fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
    pub extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*std.c.FILE;
    pub extern "c" fn fclose(stream: *std.c.FILE) c_int;
    pub extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: *std.c.FILE) usize;
    pub extern "c" fn fwrite(ptr: [*]const u8, size: usize, nmemb: usize, stream: *std.c.FILE) usize;
};

fn winRealpath(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    var buf: [4096]u8 = undefined;
    const res = c._fullpath(&buf, path_z.ptr, buf.len) orelse return error.InvalidTargetPath;
    return try alloc.dupe(u8, std.mem.span(res));
}

fn winExists(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) bool {
    const path_z = alloc.dupeSentinel(u8, path, 0) catch return false;
    defer alloc.free(path_z);
    return c._access(path_z.ptr, 0) == 0;
}

fn winStat(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ?fs.StatInfo {
    const path_z = alloc.dupeSentinel(u8, path, 0) catch return null;
    defer alloc.free(path_z);
    var st: std.c.Stat = undefined;
    if (std.c.stat(path_z.ptr, &st) != 0) return null;
    const is_dir = (st.mode & std.c.S.IFMT) == std.c.S.IFDIR;
    return .{
        .kind = if (is_dir) .directory else .file,
        .size = if (st.size >= 0) @intCast(st.size) else 0,
    };
}

fn winListDir(_: ?*anyopaque, _: std.mem.Allocator, _: []const u8) ![]fs.DirEntry {
    // Windows FindFirstFileW / FindNextFileW implementation
    return error.NotImplementedOnWindows;
}

fn winMkdirAll(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) !void {
    if (path.len == 0) return;
    if (winExists(ctx, alloc, path)) return;

    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0 and !std.mem.eql(u8, parent, path)) {
            try winMkdirAll(ctx, alloc, parent);
        }
    }

    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    if (c._mkdir(path_z.ptr) != 0 and !winExists(ctx, alloc, path)) {
        return error.MkdirFailed;
    }
}

fn winDeleteTree(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) !void {
    const info = winStat(ctx, alloc, path) orelse return;
    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    if (info.kind != .directory) {
        _ = c._unlink(path_z.ptr);
        return;
    }
    _ = c._rmdir(path_z.ptr);
}

fn winAtomicWriteFile(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, data: []const u8, _: bool) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try winMkdirAll(ctx, alloc, parent);
    }
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{path});
    defer alloc.free(tmp_path);

    const tmp_z = try alloc.dupeSentinel(u8, tmp_path, 0);
    defer alloc.free(tmp_z);
    const dst_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(dst_z);

    const f = c.fopen(tmp_z.ptr, "wb") orelse return error.OpenFileFailed;
    errdefer {
        _ = c.fclose(f);
        _ = c._unlink(tmp_z.ptr);
    }
    if (data.len > 0) {
        const written = c.fwrite(data.ptr, 1, data.len, f);
        if (written != data.len) return error.WriteFailed;
    }
    if (c.fclose(f) != 0) return error.WriteFailed;
    _ = c._unlink(dst_z.ptr);
    if (c.rename(tmp_z.ptr, dst_z.ptr) != 0) return error.RenameFailed;
}

fn winReadFileAlloc(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    const f = c.fopen(path_z.ptr, "rb") orelse return error.FileNotFound;
    defer _ = c.fclose(f);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = c.fread(&chunk, 1, chunk.len, f);
        if (n == 0) break;
        if (buf.items.len + n > max_bytes) return error.FileTooBig;
        try buf.appendSlice(alloc, chunk[0..n]);
    }
    return try buf.toOwnedSlice(alloc);
}

const vtable = fs.PlatformFs.VTable{
    .realpath = winRealpath,
    .exists = winExists,
    .stat = winStat,
    .list_dir = winListDir,
    .mkdir_all = winMkdirAll,
    .delete_tree = winDeleteTree,
    .atomic_write_file = winAtomicWriteFile,
    .read_file_alloc = winReadFileAlloc,
};

pub fn instance() fs.PlatformFs {
    return .{ .ptr = null, .vtable = &vtable };
}
