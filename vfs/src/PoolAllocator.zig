const std = @import("std");
const Crypto = @import("Crypto.zig");

pub const ServiceAccountQuota = struct {
    sa_index: usize,
    sa_id: []const u8 = "",
    total_bytes: u64,
    used_bytes: u64,
    reserved_headroom_bytes: u64 = 0,
    active_leased_bytes: u64 = 0,

    pub fn availableBytes(self: ServiceAccountQuota) u64 {
        const reserved = self.used_bytes +| self.reserved_headroom_bytes +| self.active_leased_bytes;
        if (self.total_bytes <= reserved) return 0;
        return self.total_bytes - reserved;
    }
};

pub const ExtentAllocation = struct {
    sa_index: usize,
    sa_id: []const u8,
    logical_offset: u64,
    allocated_bytes: u64,
};

/// Hexagonal upload account selection policy (`VTable` interface).
pub const UploadPolicy = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        selectAccount: *const fn (ptr: *anyopaque, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize,
    };

    pub fn selectAccount(self: UploadPolicy, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
        return self.vtable.selectAccount(self.ptr, accounts, required_bytes);
    }
};

/// Picks the account with the largest available headroom (water-filling).
pub const MostAvailablePolicy = struct {
    pub fn policy(self: *MostAvailablePolicy) UploadPolicy {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = UploadPolicy.VTable{
        .selectAccount = selectImpl,
    };

    fn selectImpl(_: *anyopaque, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
        return selectMostAvailableAccount(accounts, required_bytes);
    }
};

/// Picks the first account in slice order that has at least `required_bytes` (and > 0) available.
pub const FirstFitPolicy = struct {
    pub fn policy(self: *FirstFitPolicy) UploadPolicy {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = UploadPolicy.VTable{
        .selectAccount = selectImpl,
    };

    fn selectImpl(_: *anyopaque, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
        for (accounts, 0..) |acc, i| {
            const avail = acc.availableBytes();
            if (avail > 0 and avail >= required_bytes) return i;
        }
        return null;
    }
};

/// Picks uniformly at random among all accounts with `availableBytes() >= required_bytes` (and > 0).
/// Uses reservoir sampling in O(1) extra memory.
pub const RandomPolicy = struct {
    io: std.Io,

    pub fn policy(self: *RandomPolicy) UploadPolicy {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = UploadPolicy.VTable{
        .selectAccount = selectImpl,
    };

    fn selectImpl(ptr: *anyopaque, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
        const self: *RandomPolicy = @ptrCast(@alignCast(ptr));
        var chosen: ?usize = null;
        var eligible: u64 = 0;
        for (accounts, 0..) |acc, i| {
            const avail = acc.availableBytes();
            if (avail > 0 and avail >= required_bytes) {
                eligible += 1;
                if (eligible == 1) {
                    chosen = i;
                } else {
                    var rand_buf: [8]u8 = undefined;
                    self.io.random(&rand_buf);
                    const r = std.mem.readInt(u64, &rand_buf, .little);
                    if (r % eligible == 0) chosen = i;
                }
            }
        }
        return chosen;
    }
};

/// Pins uploads to a specific `sa_id` chosen by the user.
pub const PinnedAccountPolicy = struct {
    sa_id: []const u8,

    pub fn policy(self: *PinnedAccountPolicy) UploadPolicy {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = UploadPolicy.VTable{
        .selectAccount = selectImpl,
    };

    fn selectImpl(ptr: *anyopaque, accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
        const self: *PinnedAccountPolicy = @ptrCast(@alignCast(ptr));
        for (accounts, 0..) |acc, i| {
            if (std.mem.eql(u8, acc.sa_id, self.sa_id)) {
                const avail = acc.availableBytes();
                if (avail > 0 and avail >= required_bytes) return i;
                return null;
            }
        }
        return null;
    }
};

/// Selects the Service Account with the largest available headroom (water-filling).
pub fn selectMostAvailableAccount(accounts: []const ServiceAccountQuota, required_bytes: u64) ?usize {
    var best_idx: ?usize = null;
    var best_avail: u64 = 0;
    for (accounts, 0..) |acc, i| {
        const avail = acc.availableBytes();
        if (avail >= required_bytes and avail > best_avail) {
            best_avail = avail;
            best_idx = i;
        }
    }
    return best_idx;
}

/// Plans striped part allocations across accounts using the default `MostAvailablePolicy`.
/// Non-final extents are aligned strictly to `Crypto.PAGE_SIZE_BYTES` (256 KiB) boundaries (`037` §6.3).
pub fn planStripedAllocation(
    allocator: std.mem.Allocator,
    accounts: []const ServiceAccountQuota,
    total_bytes: u64,
    max_part_size_bytes: u64,
) ![]ExtentAllocation {
    var default_pol = MostAvailablePolicy{};
    return planStripedAllocationWithPolicy(allocator, accounts, total_bytes, max_part_size_bytes, default_pol.policy());
}

/// Plans striped part allocations across accounts using a custom `UploadPolicy`.
pub fn planStripedAllocationWithPolicy(
    allocator: std.mem.Allocator,
    accounts: []const ServiceAccountQuota,
    total_bytes: u64,
    max_part_size_bytes: u64,
    policy: UploadPolicy,
) ![]ExtentAllocation {
    if (total_bytes == 0) return allocator.alloc(ExtentAllocation, 0);

    const page_size: u64 = Crypto.PAGE_SIZE_BYTES;
    const part_cap = @max(page_size, (max_part_size_bytes / page_size) * page_size);

    const scratch = try allocator.dupe(ServiceAccountQuota, accounts);
    defer allocator.free(scratch);

    var plan: std.ArrayListUnmanaged(ExtentAllocation) = .empty;
    errdefer plan.deinit(allocator);

    var remaining = total_bytes;
    var offset: u64 = 0;

    while (remaining > 0) {
        const pos = policy.selectAccount(scratch, 1) orelse return error.InsufficientPoolQuota;
        const best_cap = scratch[pos].availableBytes();
        if (best_cap == 0) return error.InsufficientPoolQuota;

        var take = @min(remaining, @min(best_cap, part_cap));
        // If this is not the final chunk, align down to 256 KiB page boundary.
        if (take < remaining) {
            take = (take / page_size) * page_size;
            if (take == 0) return error.InsufficientPoolQuota;
        }

        try plan.append(allocator, .{
            .sa_index = scratch[pos].sa_index,
            .sa_id = scratch[pos].sa_id,
            .logical_offset = offset,
            .allocated_bytes = take,
        });

        scratch[pos].used_bytes +|= take;
        offset += take;
        remaining -= take;
    }

    return plan.toOwnedSlice(allocator);
}
