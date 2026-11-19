const std = @import("std");
const builtin = @import("builtin");

/// Platform-agnostic environment and target-convention interface (VTable pattern).
pub const PlatformEnv = struct {
    ptr: ?*anyopaque = null,
    vtable: *const VTable,

    pub const VTable = struct {
        get_env: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, key: []const u8) ?[]u8,
        home_dir: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator) ?[]u8,
        temp_dir: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator) []const u8,
        exe_ext: *const fn (ctx: ?*anyopaque) []const u8,
        shared_lib_prefix: *const fn (ctx: ?*anyopaque) []const u8,
        shared_lib_ext: *const fn (ctx: ?*anyopaque) []const u8,
        static_lib_prefix: *const fn (ctx: ?*anyopaque) []const u8,
        static_lib_ext: *const fn (ctx: ?*anyopaque) []const u8,
        native_target_triple: *const fn (ctx: ?*anyopaque) []const u8,
        unsafe_roots: *const fn (ctx: ?*anyopaque) []const []const u8,
    };

    pub fn getEnv(self: PlatformEnv, alloc: std.mem.Allocator, key: []const u8) ?[]u8 {
        return self.vtable.get_env(self.ptr, alloc, key);
    }

    pub fn homeDir(self: PlatformEnv, alloc: std.mem.Allocator) ?[]u8 {
        return self.vtable.home_dir(self.ptr, alloc);
    }

    pub fn tempDir(self: PlatformEnv, alloc: std.mem.Allocator) []const u8 {
        return self.vtable.temp_dir(self.ptr, alloc);
    }

    pub fn exeExt(self: PlatformEnv) []const u8 {
        return self.vtable.exe_ext(self.ptr);
    }

    pub fn sharedLibPrefix(self: PlatformEnv) []const u8 {
        return self.vtable.shared_lib_prefix(self.ptr);
    }

    pub fn sharedLibExt(self: PlatformEnv) []const u8 {
        return self.vtable.shared_lib_ext(self.ptr);
    }

    pub fn staticLibPrefix(self: PlatformEnv) []const u8 {
        return self.vtable.static_lib_prefix(self.ptr);
    }

    pub fn staticLibExt(self: PlatformEnv) []const u8 {
        return self.vtable.static_lib_ext(self.ptr);
    }

    pub fn nativeTargetTriple(self: PlatformEnv) []const u8 {
        return self.vtable.native_target_triple(self.ptr);
    }

    pub fn unsafeRoots(self: PlatformEnv) []const []const u8 {
        return self.vtable.unsafe_roots(self.ptr);
    }
};

fn cGetEnv(alloc: std.mem.Allocator, key: []const u8) ?[]u8 {
    const key_z = alloc.dupeSentinel(u8, key, 0) catch return null;
    defer alloc.free(key_z);
    const val_c = std.c.getenv(key_z.ptr) orelse return null;
    return alloc.dupe(u8, std.mem.span(val_c)) catch null;
}

const comptime_triple: []const u8 = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag) ++ "-" ++ @tagName(builtin.abi);

const posix_unsafe_roots = [_][]const u8{ "/", "/tmp", "/usr", "/var", "/etc", "/bin", "/sbin", "/lib" };
const macos_unsafe_roots = [_][]const u8{
    "/",
    "/tmp",
    "/usr",
    "/var",
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/System",
    "/Library",
    "/Applications",
    "/Users",
    "/Volumes",
    "/private",
    "/private/tmp",
    "/private/var",
    "/private/etc",
    "/opt/homebrew",
};
const windows_unsafe_roots = [_][]const u8{ "C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)" };

// --- Linux Implementation ---
fn linuxGetEnv(_: ?*anyopaque, alloc: std.mem.Allocator, key: []const u8) ?[]u8 {
    return cGetEnv(alloc, key);
}
fn linuxHomeDir(_: ?*anyopaque, alloc: std.mem.Allocator) ?[]u8 {
    return cGetEnv(alloc, "HOME");
}
fn linuxTempDir(_: ?*anyopaque, _: std.mem.Allocator) []const u8 {
    return "/tmp";
}
fn posixExeExt(_: ?*anyopaque) []const u8 {
    return "";
}
fn posixSharedPrefix(_: ?*anyopaque) []const u8 {
    return "lib";
}
fn linuxSharedExt(_: ?*anyopaque) []const u8 {
    return ".so";
}
fn posixStaticPrefix(_: ?*anyopaque) []const u8 {
    return "lib";
}
fn posixStaticExt(_: ?*anyopaque) []const u8 {
    return ".a";
}
fn nativeTriple(_: ?*anyopaque) []const u8 {
    return comptime_triple;
}
fn posixUnsafe(_: ?*anyopaque) []const []const u8 {
    return &posix_unsafe_roots;
}

const linux_vtable = PlatformEnv.VTable{
    .get_env = linuxGetEnv,
    .home_dir = linuxHomeDir,
    .temp_dir = linuxTempDir,
    .exe_ext = posixExeExt,
    .shared_lib_prefix = posixSharedPrefix,
    .shared_lib_ext = linuxSharedExt,
    .static_lib_prefix = posixStaticPrefix,
    .static_lib_ext = posixStaticExt,
    .native_target_triple = nativeTriple,
    .unsafe_roots = posixUnsafe,
};

// --- macOS Implementation ---
fn macosSharedExt(_: ?*anyopaque) []const u8 {
    return ".dylib";
}
fn macosUnsafe(_: ?*anyopaque) []const []const u8 {
    return &macos_unsafe_roots;
}

const macos_vtable = PlatformEnv.VTable{
    .get_env = linuxGetEnv,
    .home_dir = linuxHomeDir,
    .temp_dir = linuxTempDir,
    .exe_ext = posixExeExt,
    .shared_lib_prefix = posixSharedPrefix,
    .shared_lib_ext = macosSharedExt,
    .static_lib_prefix = posixStaticPrefix,
    .static_lib_ext = posixStaticExt,
    .native_target_triple = nativeTriple,
    .unsafe_roots = macosUnsafe,
};

// --- Windows Implementation ---
fn winHomeDir(_: ?*anyopaque, alloc: std.mem.Allocator) ?[]u8 {
    return cGetEnv(alloc, "USERPROFILE");
}
fn winTempDir(_: ?*anyopaque, _: std.mem.Allocator) []const u8 {
    return "C:\\Windows\\Temp";
}
fn winExeExt(_: ?*anyopaque) []const u8 {
    return ".exe";
}
fn winSharedPrefix(_: ?*anyopaque) []const u8 {
    return "";
}
fn winSharedExt(_: ?*anyopaque) []const u8 {
    return ".dll";
}
fn winStaticPrefix(_: ?*anyopaque) []const u8 {
    return "";
}
fn winStaticExt(_: ?*anyopaque) []const u8 {
    return ".lib";
}
fn winUnsafe(_: ?*anyopaque) []const []const u8 {
    return &windows_unsafe_roots;
}

const windows_vtable = PlatformEnv.VTable{
    .get_env = linuxGetEnv,
    .home_dir = winHomeDir,
    .temp_dir = winTempDir,
    .exe_ext = winExeExt,
    .shared_lib_prefix = winSharedPrefix,
    .shared_lib_ext = winSharedExt,
    .static_lib_prefix = winStaticPrefix,
    .static_lib_ext = winStaticExt,
    .native_target_triple = nativeTriple,
    .unsafe_roots = winUnsafe,
};

pub fn nativeEnv() PlatformEnv {
    return switch (builtin.os.tag) {
        .macos => .{ .ptr = null, .vtable = &macos_vtable },
        .windows => .{ .ptr = null, .vtable = &windows_vtable },
        else => .{ .ptr = null, .vtable = &linux_vtable },
    };
}
