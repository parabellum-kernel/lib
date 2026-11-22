const std = @import("std");
const types = @import("types.zig");
const ports = @import("ports.zig");
const errors = @import("errors.zig");

pub const FactorRegistry = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged(Entry) = .{},

    pub const Entry = struct {
        descriptor: types.FactorDescriptor,
        verifier: ports.FactorVerifier,
    };

    pub fn init(allocator: std.mem.Allocator, verifiers: []const ports.FactorVerifier) !FactorRegistry {
        var self = FactorRegistry{
            .allocator = allocator,
        };
        errdefer self.deinit();

        for (verifiers) |v| {
            const raw_desc = v.describe();
            if (raw_desc.categories.count() == 0) {
                return errors.MfaError.InvalidPolicy;
            }
            if (self.entries.contains(raw_desc.factor_id)) {
                return errors.MfaError.DuplicateFactorId;
            }

            const owned_id = try allocator.dupe(u8, raw_desc.factor_id);
            errdefer allocator.free(owned_id);

            const owned_type = try allocator.dupe(u8, raw_desc.factor_type);
            errdefer allocator.free(owned_type);

            const owned_impl = try allocator.dupe(u8, raw_desc.implementation_id);
            errdefer allocator.free(owned_impl);

            var owned_desc = raw_desc;
            owned_desc.factor_id = owned_id;
            owned_desc.factor_type = owned_type;
            owned_desc.implementation_id = owned_impl;

            try self.entries.put(allocator, owned_id, .{
                .descriptor = owned_desc,
                .verifier = v,
            });
        }

        return self;
    }

    pub fn deinit(self: *FactorRegistry) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.descriptor.factor_id);
            self.allocator.free(entry.descriptor.factor_type);
            self.allocator.free(entry.descriptor.implementation_id);
        }
        self.entries.deinit(self.allocator);
    }

    pub fn get(self: *const FactorRegistry, factor_id: []const u8) ?types.FactorDescriptor {
        if (self.entries.get(factor_id)) |entry| {
            return entry.descriptor;
        }
        return null;
    }

    pub fn getEntry(self: *const FactorRegistry, factor_id: []const u8) ?Entry {
        return self.entries.get(factor_id);
    }

    pub fn contains(self: *const FactorRegistry, factor_id: []const u8) bool {
        return self.entries.contains(factor_id);
    }
};

test "FactorRegistry init, lookup, duplicate and empty category rejection" {
    const Dummy = struct {
        desc: types.FactorDescriptor,
        fn describe(ptr: *anyopaque) types.FactorDescriptor {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.desc;
        }
        fn isEnrolled(_: *anyopaque, _: []const u8) ports.FactorVerifier.VerifierError!bool {
            return true;
        }
        fn issueChallenge(_: *anyopaque, _: ports.FactorVerifier.ChallengeContext) ports.FactorVerifier.VerifierError!ports.FactorVerifier.ChallengeEmission {
            return .not_applicable;
        }
        fn verify(_: *anyopaque, _: ports.FactorVerifier.VerifyContext, _: []const u8) ports.FactorVerifier.VerifierError!ports.FactorVerifier.VerifyResult {
            return .{ .status = .verified };
        }
        const vtable = ports.FactorVerifier.VTable{
            .describe = describe,
            .isEnrolled = isEnrolled,
            .issueChallenge = issueChallenge,
            .verify = verify,
        };
        fn verifier(self: *@This()) ports.FactorVerifier {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };

    var d1 = Dummy{ .desc = .{ .factor_id = "totp", .factor_type = "totp", .categories = .{ .possession = true } } };
    var d2 = Dummy{ .desc = .{ .factor_id = "pwd", .factor_type = "password", .categories = .{ .knowledge = true } } };
    var reg = try FactorRegistry.init(std.testing.allocator, &.{ d1.verifier(), d2.verifier() });
    defer reg.deinit();

    try std.testing.expect(reg.contains("totp"));
    try std.testing.expect(reg.contains("pwd"));
    try std.testing.expect(!reg.contains("webauthn"));
    try std.testing.expectEqualStrings("totp", reg.get("totp").?.factor_id);
    try std.testing.expectEqualStrings("totp", reg.get("totp").?.factor_type);

    var d1_dup = Dummy{ .desc = .{ .factor_id = "totp", .categories = .{ .knowledge = true } } };
    try std.testing.expectError(errors.MfaError.DuplicateFactorId, FactorRegistry.init(std.testing.allocator, &.{ d1.verifier(), d1_dup.verifier() }));

    var d_empty = Dummy{ .desc = .{ .factor_id = "bad", .categories = .{} } };
    try std.testing.expectError(errors.MfaError.InvalidPolicy, FactorRegistry.init(std.testing.allocator, &.{d_empty.verifier()}));
}
