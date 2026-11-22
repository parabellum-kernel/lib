const std = @import("std");

pub const max_policy_depth: usize = 16;
pub const max_policy_leaves: usize = 64;

pub const CategorySet = packed struct(u8) {
    knowledge: bool = false,
    possession: bool = false,
    inherence: bool = false,
    _pad: u5 = 0,

    pub fn count(self: CategorySet) u4 {
        const raw: u8 = @bitCast(self);
        return @intCast(@popCount(raw & 0x07));
    }

    pub fn merge(self: CategorySet, other: CategorySet) CategorySet {
        const a: u8 = @bitCast(self);
        const b: u8 = @bitCast(other);
        return @bitCast(a | b);
    }
};

pub const Statefulness = enum {
    stateless,
    stateful,
};

pub const BindingMode = enum {
    bound,
    unbound,
};

pub const OutcomeClass = enum {
    terminal,
    intermediate,
};

pub const EnrollmentMode = enum {
    lazy_on_challenge,
    eager_validate,
};

pub const EnrollmentVisibilityMode = enum {
    structural_only,
    enrolled_filtered,
};

pub const FactorDescriptor = struct {
    factor_id: []const u8,
    factor_type: []const u8 = "",
    implementation_id: []const u8 = "",
    categories: CategorySet = .{},
    statefulness: Statefulness = .stateless,
    requires_challenge: bool = false,
    supports_batch: bool = false,
    supports_lazy_mode: bool = true,
    is_recovery: bool = false,
};

pub const SessionLimits = struct {
    max_session_ttl_s: u64 = 600,
    max_grant_ttl_s: u64 = 300,
    max_failed_verifications_per_session: u8 = 5,
    max_challenges_per_leaf: u8 = 5,
    max_challenge_rounds_per_leaf: u8 = 8,
    max_active_challenges: u8 = 2,
    max_proof_len: usize = 4 * 1024,
    max_request_ctx_len: usize = 4 * 1024,
    max_scope_len: usize = 64,
    max_derived_ctx_len: usize = 4 * 1024,
    max_claims_len: usize = 1024,
    max_challenge_state_len: usize = 4 * 1024,
    max_state_update_len: usize = 1024,
    max_sealed_blob_len: usize = 256 * 1024,
    max_conflict_retries: u8 = 1,
    clock_skew_tolerance_s: u32 = 2,
};

pub const AssurancePolicy = struct {
    min_categories: u8 = 2,
    allow_single_factor: bool = false,
    allow_unordered_all_of: bool = false,
    allow_stateful_in_batch: bool = false,
};

test "CategorySet count and merge" {
    const a = CategorySet{ .knowledge = true };
    const b = CategorySet{ .possession = true };
    const merged = a.merge(b);
    try std.testing.expectEqual(@as(u4, 1), a.count());
    try std.testing.expectEqual(@as(u4, 2), merged.count());
}
