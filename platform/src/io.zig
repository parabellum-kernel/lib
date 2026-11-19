const std = @import("std");

/// Platform-agnostic terminal output interface (VTable pattern).
pub const Terminal = struct {
    ptr: ?*anyopaque = null,
    vtable: *const VTable,

    pub const VTable = struct {
        write_stdout: *const fn (ctx: ?*anyopaque, msg: []const u8) void,
        write_stderr: *const fn (ctx: ?*anyopaque, msg: []const u8) void,
        supports_color: *const fn (ctx: ?*anyopaque) bool,
    };

    pub fn writeStdout(self: Terminal, msg: []const u8) void {
        self.vtable.write_stdout(self.ptr, msg);
    }

    pub fn writeStderr(self: Terminal, msg: []const u8) void {
        self.vtable.write_stderr(self.ptr, msg);
    }

    pub fn supportsColor(self: Terminal) bool {
        return self.vtable.supports_color(self.ptr);
    }
};

pub const StdTerminalOptions = struct {
    quiet: bool = false,
    no_color: bool = false,
};

pub const StdTerminal = struct {
    opts: StdTerminalOptions = .{},

    pub fn terminal(self: *StdTerminal) Terminal {
        return .{ .ptr = self, .vtable = &std_vtable };
    }

    fn writeStdout(ctx: ?*anyopaque, msg: []const u8) void {
        const self: *const StdTerminal = @ptrCast(@alignCast(ctx.?));
        if (self.opts.quiet or msg.len == 0) return;
        _ = std.c.write(std.c.STDOUT_FILENO, msg.ptr, msg.len);
    }

    fn writeStderr(_: ?*anyopaque, msg: []const u8) void {
        if (msg.len == 0) return;
        _ = std.c.write(std.c.STDERR_FILENO, msg.ptr, msg.len);
    }

    fn supportsColor(ctx: ?*anyopaque) bool {
        const self: *const StdTerminal = @ptrCast(@alignCast(ctx.?));
        if (self.opts.no_color) return false;
        if (std.c.getenv("NO_COLOR")) |v| {
            if (std.mem.span(v).len > 0) return false;
        }
        return std.c.isatty(std.c.STDOUT_FILENO) != 0;
    }

    const std_vtable = Terminal.VTable{
        .write_stdout = writeStdout,
        .write_stderr = writeStderr,
        .supports_color = supportsColor,
    };
};

/// In-memory terminal implementation for unit tests.
pub const BufferTerminal = struct {
    alloc: std.mem.Allocator,
    stdout_buf: std.ArrayListUnmanaged(u8) = .empty,
    stderr_buf: std.ArrayListUnmanaged(u8) = .empty,

    pub fn init(alloc: std.mem.Allocator) BufferTerminal {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *BufferTerminal) void {
        self.stdout_buf.deinit(self.alloc);
        self.stderr_buf.deinit(self.alloc);
    }

    pub fn terminal(self: *BufferTerminal) Terminal {
        return .{ .ptr = self, .vtable = &buf_vtable };
    }

    fn writeStdout(ctx: ?*anyopaque, msg: []const u8) void {
        const self: *BufferTerminal = @ptrCast(@alignCast(ctx.?));
        self.stdout_buf.appendSlice(self.alloc, msg) catch {};
    }

    fn writeStderr(ctx: ?*anyopaque, msg: []const u8) void {
        const self: *BufferTerminal = @ptrCast(@alignCast(ctx.?));
        self.stderr_buf.appendSlice(self.alloc, msg) catch {};
    }

    fn supportsColor(_: ?*anyopaque) bool {
        return false;
    }

    const buf_vtable = Terminal.VTable{
        .write_stdout = writeStdout,
        .write_stderr = writeStderr,
        .supports_color = supportsColor,
    };
};
