const std = @import("std");
const Allocator = std.mem.Allocator;
const yaml = @import("ast.zig");

const c_stdlib = struct {
    extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
};
const c_stdio = struct {
    const FILE = opaque {};
    extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*FILE;
    extern "c" fn fclose(stream: *FILE) c_int;
    extern "c" fn fseek(stream: *FILE, offset: c_long, whence: c_int) c_int;
    extern "c" fn ftell(stream: *FILE) c_long;
    extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: *FILE) usize;
    const SEEK_SET: c_int = 0;
    const SEEK_END: c_int = 2;
};

pub const EnvError = error{
    MissingRequiredEnvVar,
    MalformedEnvExpression,
    MalformedDotEnvLine,
    OutOfMemory,
};

pub const SchemeResolverFn = *const fn (allocator: Allocator, scheme: []const u8, key: []const u8) ?[]const u8;

/// `.env` file parser and `${VAR}` / `${VAR:-default}` string interpolator.
/// Plugs into `yaml.ParseOptions` / `yaml.AstOptions` via `env.scalarHook()`.
pub const EnvInterpolator = struct {
    vars: std.StringHashMapUnmanaged([]const u8) = .{},
    use_process_env: bool = true,
    scheme_resolver: ?SchemeResolverFn = null,

    pub fn init(use_process_env: bool) EnvInterpolator {
        return .{
            .vars = .{},
            .use_process_env = use_process_env,
            .scheme_resolver = null,
        };
    }

    pub fn deinit(self: *EnvInterpolator, allocator: Allocator) void {
        self.vars.deinit(allocator);
    }

    pub fn put(self: *EnvInterpolator, allocator: Allocator, key: []const u8, value: []const u8) !void {
        try self.vars.put(allocator, key, value);
    }

    /// Returns a `yaml.ScalarHook` adapter to plug `.env` expansion into `yaml.ParseOptions`.
    pub fn scalarHook(self: *const EnvInterpolator) yaml.ScalarHook {
        return .{
            .ctx = self,
            .transformFn = transformCallback,
        };
    }

    fn transformCallback(ctx: *const anyopaque, arena: Allocator, raw: []const u8) anyerror![]const u8 {
        const self: *const EnvInterpolator = @ptrCast(@alignCast(ctx));
        return self.interpolate(arena, raw);
    }

    pub fn parseDotEnv(self: *EnvInterpolator, arena: Allocator, content: []const u8) EnvError!void {
        var line_iter = std.mem.splitScalar(u8, content, '\n');
        while (line_iter.next()) |raw_line| {
            const line_cr = std.mem.trimEnd(u8, raw_line, "\r");
            const trimmed = std.mem.trim(u8, line_cr, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            const effective = if (std.mem.startsWith(u8, trimmed, "export "))
                std.mem.trimStart(u8, trimmed["export ".len..], " \t")
            else
                trimmed;

            const eq_idx = std.mem.indexOfScalar(u8, effective, '=') orelse return error.MalformedDotEnvLine;
            const key = std.mem.trim(u8, effective[0..eq_idx], " \t");
            if (key.len == 0) return error.MalformedDotEnvLine;

            var raw_val = std.mem.trim(u8, effective[eq_idx + 1 ..], " \t");
            const is_single_quoted = raw_val.len >= 2 and raw_val[0] == '\'' and raw_val[raw_val.len - 1] == '\'';
            if (raw_val.len >= 2 and ((raw_val[0] == '"' and raw_val[raw_val.len - 1] == '"') or is_single_quoted)) {
                raw_val = raw_val[1 .. raw_val.len - 1];
            } else if (std.mem.indexOfScalar(u8, raw_val, '#')) |comment_idx| {
                if (comment_idx > 0 and (raw_val[comment_idx - 1] == ' ' or raw_val[comment_idx - 1] == '\t')) {
                    raw_val = std.mem.trimEnd(u8, raw_val[0..comment_idx], " \t");
                }
            }

            const resolved_val = if (is_single_quoted)
                raw_val
            else
                try self.interpolate(arena, raw_val);

            const owned_key_z = try arena.dupeSentinel(u8, key, 0);
            const owned_val_z = try arena.dupeSentinel(u8, resolved_val, 0);
            try self.vars.put(arena, owned_key_z, owned_val_z);
            if (self.use_process_env) {
                _ = c_stdlib.setenv(owned_key_z.ptr, owned_val_z.ptr, 0);
            }
        }
    }

    pub fn get(self: *const EnvInterpolator, key: []const u8) ?[]const u8 {
        if (self.vars.get(key)) |v| return v;
        if (self.use_process_env) {
            return getProcessEnv(key);
        }
        return null;
    }

    fn getProcessEnv(key: []const u8) ?[]const u8 {
        if (@import("builtin").link_libc) {
            var buf: [256]u8 = undefined;
            if (key.len < buf.len) {
                @memcpy(buf[0..key.len], key);
                buf[key.len] = 0;
                if (std.c.getenv(@ptrCast(&buf[0]))) |c_str| {
                    return std.mem.span(c_str);
                }
            }
        }
        if (@hasDecl(std.os, "environ")) {
            for (std.os.environ) |entry_ptr| {
                const entry = std.mem.span(entry_ptr);
                if (std.mem.indexOfScalar(u8, entry, '=')) |eq_idx| {
                    if (std.mem.eql(u8, entry[0..eq_idx], key)) {
                        return entry[eq_idx + 1 ..];
                    }
                }
            }
        }
        return null;
    }

    fn expandTilde(self: *const EnvInterpolator, arena: Allocator, val: []const u8) Allocator.Error![]const u8 {
        if (std.mem.eql(u8, val, "~")) {
            if (self.get("HOME")) |home| {
                if (home.len > 0) return arena.dupe(u8, home);
            }
        } else if (std.mem.startsWith(u8, val, "~/")) {
            if (self.get("HOME")) |home| {
                if (home.len > 0) {
                    const clean_home = std.mem.trimEnd(u8, home, "/");
                    return std.fmt.allocPrint(arena, "{s}/{s}", .{ clean_home, val[2..] });
                }
            }
        }
        return val;
    }

    pub fn interpolate(self: *const EnvInterpolator, arena: Allocator, raw: []const u8) EnvError![]const u8 {
        if (std.mem.indexOf(u8, raw, "${") == null) {
            return try self.expandTilde(arena, raw);
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        var i: usize = 0;
        while (i < raw.len) {
            if (i + 1 < raw.len and raw[i] == '$' and raw[i + 1] == '{') {
                const start_expr = i + 2;
                const rel_end = std.mem.indexOfScalar(u8, raw[start_expr..], '}') orelse
                    return error.MalformedEnvExpression;
                const expr = raw[start_expr .. start_expr + rel_end];
                if (expr.len == 0) return error.MalformedEnvExpression;

                if (std.mem.indexOf(u8, expr, ":-")) |sep_idx| {
                    const var_name = expr[0..sep_idx];
                    const default_val = expr[sep_idx + 2 ..];
                    if (var_name.len == 0) return error.MalformedEnvExpression;

                    if (self.get(var_name)) |val| {
                        if (val.len > 0) {
                            try out.appendSlice(arena, val);
                        } else {
                            try out.appendSlice(arena, default_val);
                        }
                    } else {
                        try out.appendSlice(arena, default_val);
                    }
                } else if (std.mem.indexOfScalar(u8, expr, ':')) |colon_idx| {
                    const scheme = expr[0..colon_idx];
                    const key = expr[colon_idx + 1 ..];
                    if (self.scheme_resolver) |resolver| {
                        if (resolver(arena, scheme, key)) |resolved| {
                            try out.appendSlice(arena, resolved);
                        } else {
                            return error.MissingRequiredEnvVar;
                        }
                    } else {
                        return error.MissingRequiredEnvVar;
                    }
                } else {
                    const var_name = expr;
                    const val = self.get(var_name) orelse return error.MissingRequiredEnvVar;
                    try out.appendSlice(arena, val);
                }

                i = start_expr + rel_end + 1;
            } else {
                try out.append(arena, raw[i]);
                i += 1;
            }
        }

        const result = try out.toOwnedSlice(arena);
        return try self.expandTilde(arena, result);
    }
};

fn readFileAllocC(alloc: Allocator, path: []const u8) ![]u8 {
    const path_z = try alloc.allocSentinel(u8, path.len, 0);
    @memcpy(path_z, path);
    defer alloc.free(path_z);

    const fp = c_stdio.fopen(path_z.ptr, "rb") orelse return error.FileNotFound;
    defer _ = c_stdio.fclose(fp);

    _ = c_stdio.fseek(fp, 0, c_stdio.SEEK_END);
    const sz_long = c_stdio.ftell(fp);
    if (sz_long < 0) return error.FileReadFailed;
    const sz: usize = @intCast(sz_long);
    _ = c_stdio.fseek(fp, 0, c_stdio.SEEK_SET);

    const buf = try alloc.alloc(u8, sz);
    errdefer alloc.free(buf);
    if (sz > 0) {
        const read_n = c_stdio.fread(buf.ptr, 1, sz, fp);
        if (read_n != sz) return error.FileReadFailed;
    }
    return buf;
}

/// Load a specific `.env` file into process env. Returns true if the file was found and parsed.
pub fn loadDotEnvFile(alloc: Allocator, path: []const u8) bool {
    const bytes = readFileAllocC(alloc, path) catch return false;
    var env = EnvInterpolator.init(true);
    defer env.deinit(alloc);
    env.parseDotEnv(alloc, bytes) catch {};
    return true;
}

/// Load `.env` from CWD, `configs/.env`, or `<dirname(pipeline_path)>/.env` into process env.
pub fn loadDotEnvForPipeline(alloc: Allocator, pipeline_path: []const u8) void {
    const pipe_dir = std.fs.path.dirname(pipeline_path) orelse ".";
    const pipe_env = std.fs.path.join(alloc, &.{ pipe_dir, ".env" }) catch return;
    const env_candidates = [_][]const u8{
        ".env",
        "configs/.env",
        pipe_env,
    };
    for (env_candidates) |ep| {
        if (loadDotEnvFile(alloc, ep)) break;
    }
}

pub const DotEnvEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// Parses `.env` content into key/value slices referencing `content` without mutating process env.
pub fn parseDotEnvEntries(alloc: Allocator, content: []const u8) ![]DotEnvEntry {
    var list: std.ArrayListUnmanaged(DotEnvEntry) = .empty;
    errdefer list.deinit(alloc);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const body = if (std.mem.startsWith(u8, line, "export ") or std.mem.startsWith(u8, line, "export\t"))
            std.mem.trimStart(u8, line["export".len..], " \t")
        else
            line;

        const eq_idx = std.mem.indexOfScalar(u8, body, '=') orelse continue;
        const key = std.mem.trim(u8, body[0..eq_idx], " \t");
        if (key.len == 0) continue;

        var val = std.mem.trim(u8, body[eq_idx + 1 ..], " \t");
        if (val.len >= 2 and ((val[0] == '"' and val[val.len - 1] == '"') or (val[0] == '\'' and val[val.len - 1] == '\''))) {
            val = val[1 .. val.len - 1];
        } else if (std.mem.indexOfScalar(u8, val, '#')) |hash_idx| {
            if (hash_idx > 0 and (val[hash_idx - 1] == ' ' or val[hash_idx - 1] == '\t')) {
                val = std.mem.trimEnd(u8, val[0..hash_idx], " \t");
            }
        }

        try list.append(alloc, .{ .key = key, .value = val });
    }

    return list.toOwnedSlice(alloc);
}

/// Parses `.env` content with interpolation and tilde expansion, applying unset entries to process env.
pub fn applyDotEnvContent(alloc: Allocator, content: []const u8) !usize {
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var env = EnvInterpolator.init(true);
    try env.parseDotEnv(arena, content);
    return env.vars.count();
}

fn matchDotEnvLineKey(raw_line: []const u8) ?[]const u8 {
    const line = std.mem.trim(u8, raw_line, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;

    const body = if (std.mem.startsWith(u8, line, "export ") or std.mem.startsWith(u8, line, "export\t"))
        std.mem.trimStart(u8, line["export".len..], " \t")
    else
        line;

    const eq_idx = std.mem.indexOfScalar(u8, body, '=') orelse return null;
    const key = std.mem.trim(u8, body[0..eq_idx], " \t");
    if (key.len == 0) return null;
    return key;
}

fn formatDotEnvValue(alloc: Allocator, value: []const u8) ![]u8 {
    const needs_quotes = for (value) |c| {
        if (c == ' ' or c == '\t' or c == '#' or c == '\n' or c == '\r') break true;
    } else false;
    if (!needs_quotes) return alloc.dupe(u8, value);
    return std.fmt.allocPrint(alloc, "\"{s}\"", .{value});
}

/// Returns updated `.env` content with `entries` set or updated, preserving unrelated lines and comments.
pub fn setDotEnvEntriesInContent(alloc: Allocator, existing: []const u8, entries: []const DotEnvEntry) ![]u8 {
    const seen = try alloc.alloc(bool, entries.len);
    defer alloc.free(seen);
    @memset(seen, false);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    if (existing.len > 0) {
        var lines = std.mem.splitScalar(u8, existing, '\n');
        var first = true;
        while (lines.next()) |raw_line| {
            const clean_line = std.mem.trimEnd(u8, raw_line, "\r");
            if (!first and lines.peek() == null and clean_line.len == 0) break;
            first = false;

            if (matchDotEnvLineKey(clean_line)) |line_key| {
                var replaced = false;
                for (entries, 0..) |entry, idx| {
                    if (std.mem.eql(u8, line_key, entry.key)) {
                        const fmt_val = try formatDotEnvValue(alloc, entry.value);
                        defer alloc.free(fmt_val);
                        try out.print(alloc, "{s}={s}\n", .{ entry.key, fmt_val });
                        seen[idx] = true;
                        replaced = true;
                        break;
                    }
                }
                if (replaced) continue;
            }
            try out.print(alloc, "{s}\n", .{clean_line});
        }
    }

    for (entries, 0..) |entry, idx| {
        if (!seen[idx]) {
            const fmt_val = try formatDotEnvValue(alloc, entry.value);
            defer alloc.free(fmt_val);
            try out.print(alloc, "{s}={s}\n", .{ entry.key, fmt_val });
        }
    }

    return out.toOwnedSlice(alloc);
}

/// Returns updated `.env` content with `keys` removed, preserving unrelated lines and comments.
pub fn unsetDotEnvKeysInContent(
    alloc: Allocator,
    existing: []const u8,
    keys: []const []const u8,
) !struct { content: []u8, removed: usize } {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    var removed: usize = 0;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    var first = true;
    while (lines.next()) |raw_line| {
        const clean_line = std.mem.trimEnd(u8, raw_line, "\r");
        if (!first and lines.peek() == null and clean_line.len == 0) break;
        first = false;

        if (matchDotEnvLineKey(clean_line)) |line_key| {
            var should_remove = false;
            for (keys) |k| {
                if (std.mem.eql(u8, line_key, k)) {
                    should_remove = true;
                    break;
                }
            }
            if (should_remove) {
                removed += 1;
                continue;
            }
        }
        try out.print(alloc, "{s}\n", .{clean_line});
    }

    return .{ .content = try out.toOwnedSlice(alloc), .removed = removed };
}

