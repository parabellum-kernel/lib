const std = @import("std");
const builtin = @import("builtin");

pub const EnvPair = struct {
    key: []const u8,
    value: []const u8,
};

pub const RunOptions = struct {
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    env_overrides: []const EnvPair = &.{},
    max_output_bytes: usize = 4 * 1024 * 1024,
};

pub const ProcessResult = struct {
    exit_code: u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *ProcessResult, alloc: std.mem.Allocator) void {
        alloc.free(self.stdout);
        alloc.free(self.stderr);
    }
};

/// Platform-agnostic process execution interface (VTable pattern).
/// Guarantees `argv`-only execution (no `/bin/sh -c` shell interpolation).
pub const ProcessRunner = struct {
    ptr: ?*anyopaque = null,
    vtable: *const VTable,

    pub const VTable = struct {
        run: *const fn (ctx: ?*anyopaque, alloc: std.mem.Allocator, opts: RunOptions) anyerror!ProcessResult,
    };

    pub fn run(self: ProcessRunner, alloc: std.mem.Allocator, opts: RunOptions) !ProcessResult {
        return self.vtable.run(self.ptr, alloc, opts);
    }
};

pub const ChildProcessRunner = struct {
    pub fn runner() ProcessRunner {
        return .{ .ptr = null, .vtable = &child_vtable };
    }

    fn runChild(_: ?*anyopaque, alloc: std.mem.Allocator, opts: RunOptions) !ProcessResult {
        const proc_env: std.process.Environ = if (builtin.os.tag == .windows)
            .{ .block = .global }
        else
            .{ .block = .{ .slice = @ptrCast(std.mem.span(std.c.environ)) } };

        var threaded: std.Io.Threaded = .init(alloc, .{ .environ = proc_env });
        defer threaded.deinit();
        const io = threaded.io();

        var env_map: std.process.Environ.Map = if (opts.env_overrides.len > 0)
            try proc_env.createMap(alloc)
        else
            .init(alloc);
        defer env_map.deinit();
        for (opts.env_overrides) |kv| {
            try env_map.put(kv.key, kv.value);
        }

        const res = try std.process.run(alloc, io, .{
            .argv = opts.argv,
            .cwd = if (opts.cwd) |c| .{ .path = c } else .inherit,
            .environ_map = if (opts.env_overrides.len > 0) &env_map else null,
            .stdout_limit = .limited(opts.max_output_bytes),
            .stderr_limit = .limited(opts.max_output_bytes),
        });

        const code: u8 = switch (res.term) {
            .exited => |c| c,
            .signal => |s| @intCast(@min(128 + @intFromEnum(s), 255)),
            else => 1,
        };

        return .{
            .exit_code = code,
            .stdout = res.stdout,
            .stderr = res.stderr,
        };
    }

    const child_vtable = ProcessRunner.VTable{
        .run = runChild,
    };
};
