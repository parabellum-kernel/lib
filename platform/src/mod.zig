pub const fs = @import("fs.zig");
pub const env = @import("env.zig");
pub const io = @import("io.zig");
pub const process = @import("process.zig");

pub const PlatformFs = fs.PlatformFs;
pub const PlatformEnv = env.PlatformEnv;
pub const Terminal = io.Terminal;
pub const ProcessRunner = process.ProcessRunner;

pub const PlatformServices = struct {
    filesystem: PlatformFs,
    environment: PlatformEnv,
    terminal: Terminal,
    runner: ProcessRunner,
};
