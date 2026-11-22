const std = @import("std");
const ports = @import("ports.zig");

pub const StatelessOnlyFactorStore = struct {
    pub fn store(self: *StatelessOnlyFactorStore) ports.FactorStateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn load(_: *anyopaque, _: std.mem.Allocator, _: []const u8, _: []const u8) ports.FactorStateStore.StoreError!ports.FactorStateStore.FactorStateSnapshot {
        return .{ .bytes = null, .version = 0 };
    }

    fn commit(_: *anyopaque, _: []const u8, _: []const u8, _: u64, _: []const u8) ports.FactorStateStore.StoreError!ports.FactorStateStore.CommitResult {
        return error.StoreUnavailable;
    }

    fn isPersistent(_: *anyopaque) bool {
        return false;
    }

    const vtable = ports.FactorStateStore.VTable{
        .load = load,
        .commit = commit,
        .isPersistent = isPersistent,
    };
};

pub const InMemoryAttemptTracker = struct {
    allocator: std.mem.Allocator,
    max_failures: u32 = 5,
    subject_failures: std.StringHashMapUnmanaged(u32) = .{},
    reservations: std.AutoHashMapUnmanaged(u64, PendingReservation) = .{},
    next_token: u64 = 1,

    const PendingReservation = struct {
        key: []u8,
        op: ports.AttemptTracker.AttemptOp,
    };

    pub const InitError = error{VolatileTrackerNotAcknowledged};

    pub fn init(allocator: std.mem.Allocator, acknowledge_volatile: bool, max_failures: u32) InitError!InMemoryAttemptTracker {
        if (!acknowledge_volatile) return error.VolatileTrackerNotAcknowledged;
        return .{
            .allocator = allocator,
            .max_failures = max_failures,
        };
    }

    pub fn deinit(self: *InMemoryAttemptTracker) void {
        var it = self.subject_failures.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.subject_failures.deinit(self.allocator);

        var rit = self.reservations.valueIterator();
        while (rit.next()) |r| self.allocator.free(r.key);
        self.reservations.deinit(self.allocator);
    }

    pub fn tracker(self: *InMemoryAttemptTracker) ports.AttemptTracker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn makeKey(self: *InMemoryAttemptTracker, op: ports.AttemptTracker.AttemptOp, scope: ports.AttemptTracker.AttemptScope) ![]u8 {
        return switch (op) {
            .session_start => std.fmt.allocPrint(self.allocator, "start:{s}", .{scope.subject_id}),
            .session_access => std.fmt.allocPrint(self.allocator, "access:{s}:{s}", .{ scope.source_key orelse "", scope.session_id orelse "" }),
            .challenge, .verify => std.fmt.allocPrint(self.allocator, "sub:{s}:{s}", .{ scope.subject_id, scope.factor_id orelse scope.batch_key orelse "" }),
        };
    }

    fn reserve(ptr: *anyopaque, op: ports.AttemptTracker.AttemptOp, scope: ports.AttemptTracker.AttemptScope, _: i64) ports.AttemptTracker.TrackerError!ports.AttemptTracker.ReserveDecision {
        const self: *InMemoryAttemptTracker = @ptrCast(@alignCast(ptr));
        const key = self.makeKey(op, scope) catch return error.OutOfMemory;
        errdefer self.allocator.free(key);

        const count = self.subject_failures.get(key) orelse 0;
        if (count >= self.max_failures) {
            self.allocator.free(key);
            return .{ .locked_out = .{ .retry_after_s = 60 } };
        }

        // Charge-as-failure by default (MFA-10): unsettled reservations stay charged.
        if (self.subject_failures.getPtr(key)) |val| {
            val.* = count + 1;
        } else {
            const owned_key = self.allocator.dupe(u8, key) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_key);
            self.subject_failures.put(self.allocator, owned_key, 1) catch return error.OutOfMemory;
        }

        const tok = self.next_token;
        self.next_token += 1;
        self.reservations.put(self.allocator, tok, .{ .key = key, .op = op }) catch return error.OutOfMemory;
        return .{ .granted = .{ .token = tok } };
    }

    fn settle(ptr: *anyopaque, reservation: ports.AttemptTracker.Reservation, outcome: ports.AttemptTracker.AttemptOutcome, _: i64) ports.AttemptTracker.TrackerError!void {
        const self: *InMemoryAttemptTracker = @ptrCast(@alignCast(ptr));
        const kv = self.reservations.fetchRemove(reservation.token) orelse return;
        defer self.allocator.free(kv.value.key);

        switch (outcome) {
            .verified => {
                // Refund + reset only (subject_id, factor_id) bucket, never source_key/session_start/session_access.
                if (kv.value.op == .verify or kv.value.op == .challenge) {
                    if (self.subject_failures.getPtr(kv.value.key)) |val| {
                        val.* = 0;
                    }
                }
            },
            .session_started, .released, .pending, .challenge_issued => {
                if (self.subject_failures.getPtr(kv.value.key)) |val| {
                    if (val.* > 0) val.* -= 1;
                }
            },
            .rejected, .infra_error => {
                // Keep failure charged.
            },
        }
    }

    const vtable = ports.AttemptTracker.VTable{
        .reserve = reserve,
        .settle = settle,
    };
};

test "StatelessOnlyFactorStore and InMemoryAttemptTracker" {
    var s = StatelessOnlyFactorStore{};
    const st = s.store();
    try std.testing.expect(!st.isPersistent());
    const snap = try st.load(std.testing.allocator, "u", "f");
    try std.testing.expectEqual(@as(?[]u8, null), snap.bytes);
    try std.testing.expectEqual(@as(u64, 0), snap.version);
    try std.testing.expectError(error.StoreUnavailable, st.commit("u", "f", 0, "x"));

    try std.testing.expectError(error.VolatileTrackerNotAcknowledged, InMemoryAttemptTracker.init(std.testing.allocator, false, 2));
    var tr = try InMemoryAttemptTracker.init(std.testing.allocator, true, 2);
    defer tr.deinit();
    const dec1 = try tr.tracker().reserve(.verify, .{ .subject_id = "u", .factor_id = "f" }, 100);
    try std.testing.expect(dec1 == .granted);
    try tr.tracker().settle(dec1.granted, .rejected, 100);

    const dec2 = try tr.tracker().reserve(.verify, .{ .subject_id = "u", .factor_id = "f" }, 101);
    try std.testing.expect(dec2 == .granted);
    try tr.tracker().settle(dec2.granted, .rejected, 101);

    const dec3 = try tr.tracker().reserve(.verify, .{ .subject_id = "u", .factor_id = "f" }, 102);
    try std.testing.expect(dec3 == .locked_out);
}
