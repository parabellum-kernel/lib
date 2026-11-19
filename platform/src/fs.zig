const std = @import("std");
const builtin = @import("builtin");

pub const FileKind = enum {
    file,
    directory,
    symlink,
    other,
};

pub const StatInfo = struct {
    kind: FileKind,
    size: u64,
};

pub const DirEntry = struct {
    name: []u8,
    kind: FileKind,
};

/// Platform-agnostic filesystem interface (VTable pattern).
/// All business logic consumes `PlatformFs` without OS-specific `if` branches.
pub const PlatformFs = struct {
    ptr: ?*anyopaque = null,
    vtable: *const VTable,

    pub const VTable = struct {
        realpath: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]u8,
        exists: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) bool,
        stat: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) ?StatInfo,
        list_dir: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror![]DirEntry,
        mkdir_all: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror!void,
        delete_tree: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8) anyerror!void,
        atomic_write_file: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, data: []const u8, executable: bool) anyerror!void,
        read_file_alloc: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) anyerror![]u8,
    };

    pub fn realpath(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) ![]u8 {
        return self.vtable.realpath(self.ptr, alloc, path);
    }

    pub fn exists(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) bool {
        return self.vtable.exists(self.ptr, alloc, path);
    }

    pub fn stat(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) ?StatInfo {
        return self.vtable.stat(self.ptr, alloc, path);
    }

    pub fn isDir(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) bool {
        const info = self.stat(alloc, path) orelse return false;
        return info.kind == .directory;
    }

    pub fn listDir(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) ![]DirEntry {
        return self.vtable.list_dir(self.ptr, alloc, path);
    }

    pub fn freeDirEntries(alloc: std.mem.Allocator, entries: []DirEntry) void {
        for (entries) |e| alloc.free(e.name);
        alloc.free(entries);
    }

    pub fn mkdirAll(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) !void {
        return self.vtable.mkdir_all(self.ptr, alloc, path);
    }

    pub fn deleteTree(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) !void {
        return self.vtable.delete_tree(self.ptr, alloc, path);
    }

    pub fn atomicWriteFile(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8, data: []const u8, executable: bool) !void {
        return self.vtable.atomic_write_file(self.ptr, alloc, path, data, executable);
    }

    pub fn readFileAlloc(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
        return self.vtable.read_file_alloc(self.ptr, alloc, path, max_bytes);
    }

    pub fn computeTreeBytes(self: PlatformFs, alloc: std.mem.Allocator, path: []const u8) u64 {
        const info = self.stat(alloc, path) orelse return 0;
        if (info.kind != .directory) return info.size;

        const entries = self.listDir(alloc, path) catch return 0;
        defer freeDirEntries(alloc, entries);

        var total: u64 = 0;
        for (entries) |ent| {
            const child = std.fs.path.join(alloc, &.{ path, ent.name }) catch continue;
            defer alloc.free(child);
            total += self.computeTreeBytes(alloc, child);
        }
        return total;
    }
};

const posix_fs = @import("posix_fs.zig");
const windows_fs = @import("windows_fs.zig");

pub fn nativeFs() PlatformFs {
    return switch (builtin.os.tag) {
        .windows => windows_fs.instance(),
        else => posix_fs.instance(),
    };
}
