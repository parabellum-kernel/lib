pub const fs = @import("fs.zig");
pub const env = @import("env.zig");
pub const io = @import("io.zig");
pub const process = @import("process.zig");
pub const random_access = @import("random_access.zig");

pub const PlatformFs = fs.PlatformFs;
pub const PlatformEnv = env.PlatformEnv;
pub const Terminal = io.Terminal;
pub const ProcessRunner = process.ProcessRunner;
pub const RandomAccessFile = random_access.RandomAccessFile;
pub const openRandomAccessReadOnly = random_access.openReadOnly;

pub const PlatformServices = struct {
    filesystem: PlatformFs,
    environment: PlatformEnv,
    terminal: Terminal,
    runner: ProcessRunner,
};
