const std = @import("std");
const fs = @import("fs.zig");

const c = struct {
    pub extern "c" fn realpath(path: [*:0]const u8, resolved_path: ?[*]u8) ?[*:0]u8;
    pub extern "c" fn free(ptr: ?*anyopaque) void;
    pub extern "c" fn chmod(path: [*:0]const u8, mode: std.c.mode_t) c_int;
    pub extern "c" fn mkdir(path: [*:0]const u8, mode: std.c.mode_t) c_int;
    pub extern "c" fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
    pub extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*std.c.FILE;
    pub extern "c" fn fclose(stream: *std.c.FILE) c_int;
    pub extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: *std.c.FILE) usize;
    pub extern "c" fn fwrite(ptr: [*]const u8, size: usize, nmemb: usize, stream: *std.c.FILE) usize;
};

fn ioKindToFileKind(kind: std.Io.File.Kind) fs.FileKind {
    return switch (kind) {
        .directory => .directory,
        .sym_link => .symlink,
        .file => .file,
        else => .other,
    };
}

fn posixRealpath(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    const resolved_ptr = c.realpath(path_z.ptr, null) orelse return error.InvalidTargetPath;
    defer c.free(resolved_ptr);
    return try alloc.dupe(u8, std.mem.span(resolved_ptr));
}

fn posixExists(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) bool {
    const path_z = alloc.dupeSentinel(u8, path, 0) catch return false;
    defer alloc.free(path_z);
    return std.c.access(path_z.ptr, std.c.F_OK) == 0;
}

fn posixStat(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ?fs.StatInfo {
    var threaded: std.Io.Threaded = .init(alloc, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    const st = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return null;
    return .{
        .kind = ioKindToFileKind(st.kind),
        .size = st.size,
    };
}

fn posixListDir(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ![]fs.DirEntry {
    const dir_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(dir_z);

    const dir = std.c.opendir(dir_z.ptr) orelse return error.OpenDirFailed;
    defer _ = std.c.closedir(dir);

    var entries: std.ArrayListUnmanaged(fs.DirEntry) = .empty;
    errdefer {
        for (entries.items) |e| alloc.free(e.name);
        entries.deinit(alloc);
    }

    while (std.c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(&ent.name, 0);
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;

        const child_path = try std.fs.path.join(alloc, &.{ path, name });
        defer alloc.free(child_path);
        const child_stat = posixStat(ctx, alloc, child_path);

        try entries.append(alloc, .{
            .name = try alloc.dupe(u8, name),
            .kind = if (child_stat) |s| s.kind else .other,
        });
    }

    return try entries.toOwnedSlice(alloc);
}

fn posixMkdirAll(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) !void {
    if (path.len == 0) return;
    if (posixExists(ctx, alloc, path)) return;

    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0 and !std.mem.eql(u8, parent, path)) {
            try posixMkdirAll(ctx, alloc, parent);
        }
    }

    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    if (c.mkdir(path_z.ptr, 0o755) != 0) {
        if (!posixExists(ctx, alloc, path)) {
            return error.MkdirFailed;
        }
    }
}

fn posixDeleteTree(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) !void {
    const info = posixStat(ctx, alloc, path) orelse return;
    if (info.kind != .directory) {
        const path_z = try alloc.dupeSentinel(u8, path, 0);
        defer alloc.free(path_z);
        _ = std.c.unlink(path_z.ptr);
        return;
    }

    const entries = try posixListDir(ctx, alloc, path);
    defer fs.PlatformFs.freeDirEntries(alloc, entries);

    for (entries) |ent| {
        const child = try std.fs.path.join(alloc, &.{ path, ent.name });
        defer alloc.free(child);
        try posixDeleteTree(ctx, alloc, child);
    }

    const path_z = try alloc.dupeSentinel(u8, path, 0);
    defer alloc.free(path_z);
    _ = std.c.rmdir(path_z.ptr);
}

fn posixAtomicWriteFile(ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, data: []const u8, executable: bool) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try posixMkdirAll(ctx, alloc, parent);
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
        _ = std.c.unlink(tmp_z.ptr);
    }

    if (data.len > 0) {
        const written = c.fwrite(data.ptr, 1, data.len, f);
        if (written != data.len) return error.WriteFailed;
    }
    if (c.fclose(f) != 0) return error.WriteFailed;

    const mode: std.c.mode_t = if (executable) 0o755 else 0o644;
    _ = c.chmod(tmp_z.ptr, mode);

    if (c.rename(tmp_z.ptr, dst_z.ptr) != 0) {
        _ = std.c.unlink(tmp_z.ptr);
        return error.RenameFailed;
    }
}

fn posixReadFileAlloc(_: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
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
    .realpath = posixRealpath,
    .exists = posixExists,
    .stat = posixStat,
    .list_dir = posixListDir,
    .mkdir_all = posixMkdirAll,
    .delete_tree = posixDeleteTree,
    .atomic_write_file = posixAtomicWriteFile,
    .read_file_alloc = posixReadFileAlloc,
};

pub fn instance() fs.PlatformFs {
    return .{ .ptr = null, .vtable = &vtable };
}
