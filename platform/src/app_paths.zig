const std = @import("std");
const builtin = @import("builtin");
const fs_mod = @import("fs.zig");
const env_mod = @import("env.zig");

const c_stdlib = if (builtin.os.tag == .windows) struct {
    extern "c" fn _putenv_s(name: [*:0]const u8, value: [*:0]const u8) c_int;
} else struct {
    extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
};

fn nonEmptyEnv(env: env_mod.PlatformEnv, alloc: std.mem.Allocator, key: []const u8) ?[]u8 {
    const val = env.getEnv(alloc, key) orelse return null;
    if (val.len == 0) {
        alloc.free(val);
        return null;
    }
    return val;
}

/// Sets process environment variable `name` to `val` only if it is not already set and non-empty.
pub fn setDefaultEnv(alloc: std.mem.Allocator, name: []const u8, val: []const u8) void {
    const env = env_mod.nativeEnv();
    if (nonEmptyEnv(env, alloc, name)) |existing| {
        alloc.free(existing);
        return;
    }
    const name_z = alloc.dupeSentinel(u8, name, 0) catch return;
    defer alloc.free(name_z);
    const val_z = alloc.dupeSentinel(u8, val, 0) catch return;
    defer alloc.free(val_z);

    if (builtin.os.tag == .windows) {
        _ = c_stdlib._putenv_s(name_z.ptr, val_z.ptr);
    } else {
        _ = c_stdlib.setenv(name_z.ptr, val_z.ptr, 0);
    }
}

/// Exports `PARABELLUM_EXE_DIR` to the physical directory containing the running executable
/// (if not already set), so `.env` and YAML configs can reference `${PARABELLUM_EXE_DIR}`.
pub fn exportExeDirEnv(alloc: std.mem.Allocator) void {
    const exe_dir = std.process.executableDirPathAlloc(std.Options.debug_io, alloc) catch return;
    defer alloc.free(exe_dir);
    setDefaultEnv(alloc, "PARABELLUM_EXE_DIR", exe_dir);
}

/// Resolves the per-user application data directory using `PlatformEnv`.
/// Precedence: `<ENV_PREFIX>_DATA_DIR` -> `XDG_DATA_HOME/<app_name>` -> `LOCALAPPDATA/<app_name>`
/// -> `<home_dir>/.local/share/<app_name>` -> `./data`.
pub fn resolveDataDir(alloc: std.mem.Allocator, env_prefix: []const u8, app_name: []const u8) ![]u8 {
    const env = env_mod.nativeEnv();
    const override_key = try std.fmt.allocPrint(alloc, "{s}_DATA_DIR", .{env_prefix});
    defer alloc.free(override_key);
    if (nonEmptyEnv(env, alloc, override_key)) |dir| return dir;

    if (nonEmptyEnv(env, alloc, "XDG_DATA_HOME")) |xdg| {
        defer alloc.free(xdg);
        return std.fs.path.join(alloc, &.{ xdg, app_name });
    }
    if (nonEmptyEnv(env, alloc, "LOCALAPPDATA")) |local| {
        defer alloc.free(local);
        return std.fs.path.join(alloc, &.{ local, app_name });
    }
    if (env.homeDir(alloc)) |home| {
        defer alloc.free(home);
        return std.fs.path.join(alloc, &.{ home, ".local", "share", app_name });
    }
    return alloc.dupe(u8, "./data");
}

/// Resolves a config file using `PlatformFs` and `PlatformEnv`, supporting both
/// user-level overrides (`XDG_CONFIG_HOME`, `~/.config`, `%APPDATA%`) and
/// portable bundle layouts (`<exe_dir>/configs`, `<exe_dir>/../configs`).
pub fn resolveConfigFile(alloc: std.mem.Allocator, env_prefix: []const u8, app_name: []const u8, filename: []const u8) ![]u8 {
    const fs = fs_mod.nativeFs();
    const env = env_mod.nativeEnv();

    const override_key = try std.fmt.allocPrint(alloc, "{s}_CONFIG_DIR", .{env_prefix});
    defer alloc.free(override_key);
    if (nonEmptyEnv(env, alloc, override_key)) |dir| {
        defer alloc.free(dir);
        return std.fs.path.join(alloc, &.{ dir, filename });
    }
    if (nonEmptyEnv(env, alloc, "PARABELLUM_CONFIG_DIR")) |pdir| {
        defer alloc.free(pdir);
        const direct_path = try std.fs.path.join(alloc, &.{ pdir, filename });
        if (fs.exists(alloc, direct_path)) return direct_path;
        alloc.free(direct_path);

        return std.fs.path.join(alloc, &.{ pdir, app_name, filename });
    }
    if (nonEmptyEnv(env, alloc, "XDG_CONFIG_HOME")) |xdg| {
        defer alloc.free(xdg);
        const p_path = try std.fs.path.join(alloc, &.{ xdg, "parabellum", app_name, filename });
        if (fs.exists(alloc, p_path)) return p_path;
        alloc.free(p_path);

        const v_path = try std.fs.path.join(alloc, &.{ xdg, app_name, filename });
        if (fs.exists(alloc, v_path)) return v_path;
        alloc.free(v_path);
    }
    if (env.homeDir(alloc)) |home| {
        defer alloc.free(home);
        const p_path = try std.fs.path.join(alloc, &.{ home, ".config", "parabellum", app_name, filename });
        if (fs.exists(alloc, p_path)) return p_path;
        alloc.free(p_path);

        const v_path = try std.fs.path.join(alloc, &.{ home, ".config", app_name, filename });
        if (fs.exists(alloc, v_path)) return v_path;
        alloc.free(v_path);
    }
    if (nonEmptyEnv(env, alloc, "APPDATA")) |appdata| {
        defer alloc.free(appdata);
        const p_path = try std.fs.path.join(alloc, &.{ appdata, "parabellum", app_name, filename });
        if (fs.exists(alloc, p_path)) return p_path;
        alloc.free(p_path);
    }
    if (std.process.executableDirPathAlloc(std.Options.debug_io, alloc)) |exe_dir| {
        defer alloc.free(exe_dir);
        const sibling_cfg = try std.fs.path.join(alloc, &.{ exe_dir, "configs", filename });
        if (fs.exists(alloc, sibling_cfg)) return sibling_cfg;
        alloc.free(sibling_cfg);

        const parent_cfg = try std.fs.path.join(alloc, &.{ exe_dir, "..", "configs", filename });
        if (fs.exists(alloc, parent_cfg)) return parent_cfg;
        alloc.free(parent_cfg);
    } else |_| {}

    return std.fs.path.join(alloc, &.{ "configs", filename });
}
