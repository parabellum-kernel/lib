const std = @import("std");
const crypto = @import("parabellum_crypto");
const primitives = @import("primitives.zig");
const types = @import("types.zig");
const ports = @import("ports.zig");
const errors = @import("errors.zig");
const policy = @import("policy.zig");
const registry_mod = @import("registry.zig");

pub const SessionStatus = enum(u8) {
    active = 0,
    satisfied = 1,
    consumed = 2,
    invalidated = 3,
    expired = 4,
};

pub const ChallengedData = struct {
    factor_challenge_nonce: [32]u8,
    issued_at: i64,
    expires_at: i64,
    challenge_state: ?[]u8 = null,
    decoy: bool = false,
    rounds: u8 = 0,
    active_seq: u64 = 0,
};

pub const LeafPhase = union(enum) {
    idle,
    challenged: ChallengedData,
    satisfied,
};

pub const FactorOutput = struct {
    factor_id: []u8,
    verified_at: i64 = 0,
    derived_ctx: ?[]u8 = null,
    claims: ?[]u8 = null,
    contributing: bool = false,

    pub fn deinit(self: *FactorOutput, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        const sec = secret_allocator orelse allocator;
        if (self.factor_id.len > 0) allocator.free(self.factor_id);
        if (self.derived_ctx) |ctx| {
            primitives.wipe(ctx);
            sec.free(ctx);
        }
        if (self.claims) |c| allocator.free(c);
        self.* = undefined;
    }
};

pub const LeafSlot = struct {
    factor_id: []u8,
    phase: LeafPhase = .idle,
    challenges_issued: u8 = 0,
    output: FactorOutput,

    pub fn deinit(self: *LeafSlot, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        const sec = secret_allocator orelse allocator;
        if (self.factor_id.len > 0) allocator.free(self.factor_id);
        switch (self.phase) {
            .challenged => |cd| {
                if (cd.challenge_state) |cs| {
                    primitives.wipe(cs);
                    sec.free(cs);
                }
            },
            else => {},
        }
        self.output.deinit(allocator, secret_allocator);
        self.* = undefined;
    }
};

pub const SessionState = struct {
    session_id: []u8,
    subject_id: []u8,
    action_scope: []u8,
    policy_fingerprint: [32]u8,
    status: SessionStatus = .active,
    limits: types.SessionLimits = .{},
    assurance: types.AssurancePolicy = .{},
    binding_mode: types.BindingMode = .bound,
    binding_hash: ?[32]u8 = null,
    outcome_class: types.OutcomeClass = .terminal,
    enrollment_mode: types.EnrollmentMode = .lazy_on_challenge,
    version: u64 = 1,
    issued_at: i64,
    last_activity_at: i64,
    expires_at: i64,
    completed_at: ?i64 = null,
    failed_verifications: u16 = 0,
    used_recovery: bool = false,
    next_active_seq: u64 = 1,
    leaf_slots: []LeafSlot,

    pub fn deinit(self: *SessionState, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.subject_id);
        allocator.free(self.action_scope);
        for (self.leaf_slots) |*slot| {
            slot.deinit(allocator, secret_allocator);
        }
        allocator.free(self.leaf_slots);
        self.* = undefined;
    }

    pub const OpenExpectations = struct {
        session_id: []const u8,
        policy_fingerprint: [32]u8,
        expected_version: u64,
        aad_extra: []const u8 = "",
    };

    fn buildAad(
        allocator: std.mem.Allocator,
        session_id: []const u8,
        policy_fingerprint: [32]u8,
        version: u64,
        aad_extra: []const u8,
    ) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        var len_bytes: [4]u8 = undefined;

        std.mem.writeInt(u32, &len_bytes, @intCast(session_id.len), .little);
        try buf.appendSlice(allocator, &len_bytes);
        try buf.appendSlice(allocator, session_id);

        std.mem.writeInt(u32, &len_bytes, 32, .little);
        try buf.appendSlice(allocator, &len_bytes);
        try buf.appendSlice(allocator, &policy_fingerprint);

        var ver_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &ver_bytes, version, .little);
        try buf.appendSlice(allocator, &ver_bytes);

        try buf.appendSlice(allocator, aad_extra);
        return buf.toOwnedSlice(allocator);
    }

    pub fn seal(
        self: *const SessionState,
        allocator: std.mem.Allocator,
        secret_allocator: ?std.mem.Allocator,
        random: ports.RandomPort,
        sealer: ports.StateSealer,
        aad_extra: []const u8,
    ) (errors.MfaError || errors.InfraError)![]u8 {
        const sec = secret_allocator orelse allocator;
        var w = crypto.BinaryWriter.init(sec);
        defer {
            primitives.wipe(w.buf.items);
            w.deinit();
        }

        // Deterministic serialization
        w.writeSlice(self.session_id) catch |e| return mapWriteErr(e);
        w.writeSlice(self.subject_id) catch |e| return mapWriteErr(e);
        w.writeSlice(self.action_scope) catch |e| return mapWriteErr(e);
        w.writeBytes(&self.policy_fingerprint) catch |e| return mapWriteErr(e);
        w.writeU8(@intFromEnum(self.status)) catch |e| return mapWriteErr(e);
        w.writeU8(@intFromEnum(self.binding_mode)) catch |e| return mapWriteErr(e);
        if (self.binding_hash) |bh| {
            w.writeU8(1) catch |e| return mapWriteErr(e);
            w.writeBytes(&bh) catch |e| return mapWriteErr(e);
        } else {
            w.writeU8(0) catch |e| return mapWriteErr(e);
        }
        w.writeU8(@intFromEnum(self.outcome_class)) catch |e| return mapWriteErr(e);
        w.writeU8(@intFromEnum(self.enrollment_mode)) catch |e| return mapWriteErr(e);
        w.writeInt(u64, self.version) catch |e| return mapWriteErr(e);
        w.writeInt(i64, self.issued_at) catch |e| return mapWriteErr(e);
        w.writeInt(i64, self.last_activity_at) catch |e| return mapWriteErr(e);
        w.writeInt(i64, self.expires_at) catch |e| return mapWriteErr(e);
        if (self.completed_at) |ca| {
            w.writeU8(1) catch |e| return mapWriteErr(e);
            w.writeInt(i64, ca) catch |e| return mapWriteErr(e);
        } else {
            w.writeU8(0) catch |e| return mapWriteErr(e);
        }
        w.writeInt(u16, self.failed_verifications) catch |e| return mapWriteErr(e);
        w.writeBool(self.used_recovery) catch |e| return mapWriteErr(e);
        w.writeInt(u64, self.next_active_seq) catch |e| return mapWriteErr(e);
        try writeLimits(&w, self.limits);
        w.writeU8(self.assurance.min_categories) catch |e| return mapWriteErr(e);
        w.writeBool(self.assurance.allow_single_factor) catch |e| return mapWriteErr(e);
        w.writeBool(self.assurance.allow_unordered_all_of) catch |e| return mapWriteErr(e);
        w.writeBool(self.assurance.allow_stateful_in_batch) catch |e| return mapWriteErr(e);
        w.writeInt(u32, @intCast(self.leaf_slots.len)) catch |e| return mapWriteErr(e);

        for (self.leaf_slots) |slot| {
            w.writeSlice(slot.factor_id) catch |e| return mapWriteErr(e);
            w.writeU8(slot.challenges_issued) catch |e| return mapWriteErr(e);
            switch (slot.phase) {
                .idle => w.writeU8(0) catch |e| return mapWriteErr(e),
                .challenged => |cd| {
                    w.writeU8(1) catch |e| return mapWriteErr(e);
                    w.writeBytes(&cd.factor_challenge_nonce) catch |e| return mapWriteErr(e);
                    w.writeInt(i64, cd.issued_at) catch |e| return mapWriteErr(e);
                    w.writeInt(i64, cd.expires_at) catch |e| return mapWriteErr(e);
                    w.writeOptSlice(cd.challenge_state) catch |e| return mapWriteErr(e);
                    w.writeBool(cd.decoy) catch |e| return mapWriteErr(e);
                    w.writeU8(cd.rounds) catch |e| return mapWriteErr(e);
                    w.writeInt(u64, cd.active_seq) catch |e| return mapWriteErr(e);
                },
                .satisfied => w.writeU8(2) catch |e| return mapWriteErr(e),
            }
            w.writeInt(i64, slot.output.verified_at) catch |e| return mapWriteErr(e);
            w.writeOptSlice(slot.output.derived_ctx) catch |e| return mapWriteErr(e);
            w.writeOptSlice(slot.output.claims) catch |e| return mapWriteErr(e);
            w.writeBool(slot.output.contributing) catch |e| return mapWriteErr(e);
        }

        const aad = buildAad(allocator, self.session_id, self.policy_fingerprint, self.version, aad_extra) catch return errors.InfraError.OutOfMemory;
        defer allocator.free(aad);

        const blob = sealer.seal(allocator, random, w.buf.items, aad) catch |e| switch (e) {
            error.OutOfMemory => return errors.InfraError.OutOfMemory,
            else => return errors.InfraError.SealError,
        };
        if (blob.len > self.limits.max_sealed_blob_len) {
            allocator.free(blob);
            return errors.MfaError.LimitExceeded;
        }
        return blob;
    }

    pub fn open(
        allocator: std.mem.Allocator,
        secret_allocator: ?std.mem.Allocator,
        sealer: ports.StateSealer,
        blob: []const u8,
        expected: OpenExpectations,
        max_sealed_blob_len: usize,
    ) (errors.MfaError || errors.InfraError)!SessionState {
        if (blob.len > max_sealed_blob_len) {
            return errors.MfaError.LimitExceeded;
        }
        const sec = secret_allocator orelse allocator;
        const aad = buildAad(allocator, expected.session_id, expected.policy_fingerprint, expected.expected_version, expected.aad_extra) catch return errors.InfraError.OutOfMemory;
        defer allocator.free(aad);

        const pt = sealer.open(sec, blob, aad) catch |e| switch (e) {
            error.OutOfMemory => return errors.InfraError.OutOfMemory,
            error.OpenFailed => return errors.MfaError.InvalidSessionState,
            else => return errors.InfraError.SealError,
        };
        defer {
            primitives.wipe(pt);
            sec.free(pt);
        }

        var r = crypto.BinaryReader.init(pt);
        const session_id = r.readSlice(allocator) catch |e| return mapReadErr(e);
        errdefer allocator.free(session_id);
        const subject_id = r.readSlice(allocator) catch |e| return mapReadErr(e);
        errdefer allocator.free(subject_id);
        const action_scope = r.readSlice(allocator) catch |e| return mapReadErr(e);
        errdefer allocator.free(action_scope);
        const fp = r.readBytes(32) catch |e| return mapReadErr(e);
        const status = r.readEnum(SessionStatus) catch |e| return mapReadErr(e);
        const binding_mode = r.readEnum(types.BindingMode) catch |e| return mapReadErr(e);
        const has_bh = r.readBool() catch |e| return mapReadErr(e);
        const binding_hash: ?[32]u8 = if (has_bh) (r.readBytes(32) catch |e| return mapReadErr(e)) else null;
        const outcome_class = r.readEnum(types.OutcomeClass) catch |e| return mapReadErr(e);
        const enrollment_mode = r.readEnum(types.EnrollmentMode) catch |e| return mapReadErr(e);
        const version = r.readInt(u64) catch |e| return mapReadErr(e);
        const issued_at = r.readInt(i64) catch |e| return mapReadErr(e);
        const last_activity_at = r.readInt(i64) catch |e| return mapReadErr(e);
        const expires_at = r.readInt(i64) catch |e| return mapReadErr(e);
        const has_ca = r.readBool() catch |e| return mapReadErr(e);
        const completed_at: ?i64 = if (has_ca) (r.readInt(i64) catch |e| return mapReadErr(e)) else null;
        const failed_verifications = r.readInt(u16) catch |e| return mapReadErr(e);
        const used_recovery = r.readBool() catch |e| return mapReadErr(e);
        const next_active_seq = r.readInt(u64) catch |e| return mapReadErr(e);
        const limits = try readLimits(&r);
        const assurance = types.AssurancePolicy{
            .min_categories = r.readU8() catch |e| return mapReadErr(e),
            .allow_single_factor = r.readBool() catch |e| return mapReadErr(e),
            .allow_unordered_all_of = r.readBool() catch |e| return mapReadErr(e),
            .allow_stateful_in_batch = r.readBool() catch |e| return mapReadErr(e),
        };
        const slot_count = r.readInt(u32) catch |e| return mapReadErr(e);

        const slots = try allocator.alloc(LeafSlot, slot_count);
        var initialized: usize = 0;
        errdefer {
            for (slots[0..initialized]) |*s| s.deinit(allocator, secret_allocator);
            allocator.free(slots);
        }

        for (0..slot_count) |i| {
            const fid = r.readSlice(allocator) catch |e| return mapReadErr(e);
            errdefer allocator.free(fid);
            const ch_issued = r.readU8() catch |e| return mapReadErr(e);
            const phase_tag = r.readU8() catch |e| return mapReadErr(e);
            const phase: LeafPhase = switch (phase_tag) {
                0 => .idle,
                1 => blk: {
                    const nonce = r.readBytes(32) catch |e| return mapReadErr(e);
                    const c_iss = r.readInt(i64) catch |e| return mapReadErr(e);
                    const c_exp = r.readInt(i64) catch |e| return mapReadErr(e);
                    const c_state = r.readOptSlice(sec) catch |e| return mapReadErr(e);
                    errdefer if (c_state) |cs| {
                        primitives.wipe(cs);
                        sec.free(cs);
                    };
                    const decoy = r.readBool() catch |e| return mapReadErr(e);
                    const rounds = r.readU8() catch |e| return mapReadErr(e);
                    const a_seq = r.readInt(u64) catch |e| return mapReadErr(e);
                    break :blk .{ .challenged = .{
                        .factor_challenge_nonce = nonce,
                        .issued_at = c_iss,
                        .expires_at = c_exp,
                        .challenge_state = c_state,
                        .decoy = decoy,
                        .rounds = rounds,
                        .active_seq = a_seq,
                    } };
                },
                2 => .satisfied,
                else => return errors.MfaError.InvalidSessionState,
            };
            errdefer switch (phase) {
                .challenged => |cd| if (cd.challenge_state) |cs| {
                    primitives.wipe(cs);
                    sec.free(cs);
                },
                else => {},
            };
            const v_at = r.readInt(i64) catch |e| return mapReadErr(e);
            const d_ctx = r.readOptSlice(sec) catch |e| return mapReadErr(e);
            errdefer if (d_ctx) |dc| {
                primitives.wipe(dc);
                sec.free(dc);
            };
            const claims = r.readOptSlice(allocator) catch |e| return mapReadErr(e);
            errdefer if (claims) |cl| allocator.free(cl);
            const contrib = r.readBool() catch |e| return mapReadErr(e);
            const out_fid = try allocator.dupe(u8, fid);

            slots[i] = .{
                .factor_id = fid,
                .phase = phase,
                .challenges_issued = ch_issued,
                .output = .{
                    .factor_id = out_fid,
                    .verified_at = v_at,
                    .derived_ctx = d_ctx,
                    .claims = claims,
                    .contributing = contrib,
                },
            };
            initialized += 1;
        }

        r.expectEof() catch |e| return mapReadErr(e);

        return .{
            .session_id = session_id,
            .subject_id = subject_id,
            .action_scope = action_scope,
            .policy_fingerprint = fp,
            .status = status,
            .limits = limits,
            .assurance = assurance,
            .binding_mode = binding_mode,
            .binding_hash = binding_hash,
            .outcome_class = outcome_class,
            .enrollment_mode = enrollment_mode,
            .version = version,
            .issued_at = issued_at,
            .last_activity_at = last_activity_at,
            .expires_at = expires_at,
            .completed_at = completed_at,
            .failed_verifications = failed_verifications,
            .used_recovery = used_recovery,
            .next_active_seq = next_active_seq,
            .leaf_slots = slots,
        };
    }
};

pub const ChainOutcome = struct {
    subject_id: []u8,
    action_scope: []u8,
    session_id: []u8,
    policy_fingerprint: [32]u8,
    binding_mode: types.BindingMode,
    binding_hash: ?[32]u8,
    max_grant_ttl_s: u64,
    completed_at: i64,
    expires_at: i64,
    categories_mask: types.CategorySet,
    used_recovery: bool,
    satisfied_factors: []FactorOutput,

    pub fn deinit(self: *ChainOutcome, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        allocator.free(self.subject_id);
        allocator.free(self.action_scope);
        allocator.free(self.session_id);
        for (self.satisfied_factors) |*f| f.deinit(allocator, secret_allocator);
        allocator.free(self.satisfied_factors);
        self.* = undefined;
    }
};

pub const IntermediateOutcome = struct {
    subject_id: []u8,
    action_scope: []u8,
    session_id: []u8,
    policy_fingerprint: [32]u8,
    binding_mode: types.BindingMode,
    binding_hash: ?[32]u8,
    max_grant_ttl_s: u64,
    completed_at: i64,
    expires_at: i64,
    categories_mask: types.CategorySet,
    used_recovery: bool,
    satisfied_factors: []FactorOutput,

    pub fn deinit(self: *IntermediateOutcome, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        allocator.free(self.subject_id);
        allocator.free(self.action_scope);
        allocator.free(self.session_id);
        for (self.satisfied_factors) |*f| f.deinit(allocator, secret_allocator);
        allocator.free(self.satisfied_factors);
        self.* = undefined;
    }
};

pub fn checkInvariants(
    state: *const SessionState,
    chain: policy.SecurityChain,
    registry: *const registry_mod.FactorRegistry,
) errors.MfaError!void {
    if (state.last_activity_at < state.issued_at) return errors.MfaError.InvalidSessionState;
    if (state.expires_at < state.issued_at) return errors.MfaError.InvalidSessionState;
    if (state.failed_verifications > state.limits.max_failed_verifications_per_session) {
        return errors.MfaError.InvalidSessionState;
    }

    var leaves: [types.max_policy_leaves]policy.LeafNode = undefined;
    var leaf_count: usize = 0;
    collectPolicyLeaves(&chain.root, &leaves, &leaf_count) catch return errors.MfaError.InvalidSessionState;
    if (state.leaf_slots.len != leaf_count) return errors.MfaError.InvalidSessionState;

    var active_challenges: u16 = 0;
    for (state.leaf_slots, 0..) |slot, i| {
        if (!std.mem.eql(u8, slot.factor_id, leaves[i].factor_id) or
            !std.mem.eql(u8, slot.output.factor_id, leaves[i].factor_id))
        {
            return errors.MfaError.InvalidSessionState;
        }
        if (slot.challenges_issued > state.limits.max_challenges_per_leaf) {
            return errors.MfaError.InvalidSessionState;
        }
        switch (slot.phase) {
            .challenged => |cd| {
                active_challenges += 1;
                if (cd.rounds > state.limits.max_challenge_rounds_per_leaf) {
                    return errors.MfaError.InvalidSessionState;
                }
                if (cd.issued_at < state.issued_at or cd.issued_at > state.last_activity_at) {
                    return errors.MfaError.InvalidSessionState;
                }
                if (cd.challenge_state) |cs| {
                    if (cs.len > state.limits.max_challenge_state_len) {
                        return errors.MfaError.InvalidSessionState;
                    }
                }
            },
            .satisfied => {
                if (slot.output.verified_at < state.issued_at or slot.output.verified_at > state.last_activity_at) {
                    return errors.MfaError.InvalidSessionState;
                }
                if (slot.output.derived_ctx) |dc| {
                    if (dc.len > state.limits.max_derived_ctx_len) {
                        return errors.MfaError.InvalidSessionState;
                    }
                }
                if (slot.output.claims) |cl| {
                    if (cl.len > state.limits.max_claims_len) {
                        return errors.MfaError.InvalidSessionState;
                    }
                }
                for (leaves[i].reads_ctx_from) |dep| {
                    if (!dep.required) continue;
                    var prod_ok = false;
                    for (0..leaf_count) |j| {
                        if (std.mem.eql(u8, leaves[j].factor_id, dep.factor_id)) {
                            if (state.leaf_slots[j].phase == .satisfied and state.leaf_slots[j].output.derived_ctx != null) {
                                prod_ok = true;
                            }
                            break;
                        }
                    }
                    if (!prod_ok) return errors.MfaError.InvalidSessionState;
                }
            },
            .idle => {},
        }
    }
    if (active_challenges > state.limits.max_active_challenges) {
        return errors.MfaError.InvalidSessionState;
    }

    var idx: usize = 0;
    _ = try checkOrderedSubtree(&chain.root, state.leaf_slots, &idx, registry);
}

fn collectPolicyLeaves(node: *const policy.PolicyNode, out: *[types.max_policy_leaves]policy.LeafNode, count: *usize) !void {
    switch (node.*) {
        .leaf => |l| {
            if (count.* >= types.max_policy_leaves) return error.TooManyLeaves;
            out[count.*] = l;
            count.* += 1;
        },
        .all_of, .batch_all_of, .any_of, .ordered => |children| {
            for (children) |*c| try collectPolicyLeaves(c, out, count);
        },
        .threshold => |th| {
            for (th.nodes) |*c| try collectPolicyLeaves(c, out, count);
        },
    }
}

const SubtreeEval = struct {
    satisfied: bool,
    has_any_satisfied: bool,
    cats: types.CategorySet = .{},
};

fn checkOrderedSubtree(
    node: *const policy.PolicyNode,
    slots: []const LeafSlot,
    idx: *usize,
    registry: *const registry_mod.FactorRegistry,
) errors.MfaError!SubtreeEval {
    switch (node.*) {
        .leaf => |l| {
            const sat = slots[idx.*].phase == .satisfied;
            idx.* += 1;
            const cats = if (sat) (if (registry.get(l.factor_id)) |d| d.categories else types.CategorySet{}) else types.CategorySet{};
            return .{ .satisfied = sat, .has_any_satisfied = sat, .cats = cats };
        },
        .all_of, .batch_all_of => |children| {
            var all_sat = true;
            var any_sat = false;
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = try checkOrderedSubtree(c, slots, idx, registry);
                all_sat = all_sat and r.satisfied;
                any_sat = any_sat or r.has_any_satisfied;
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = all_sat, .has_any_satisfied = any_sat, .cats = cats };
        },
        .any_of => |children| {
            var any_child_sat = false;
            var any_sat = false;
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = try checkOrderedSubtree(c, slots, idx, registry);
                if (r.satisfied and !any_child_sat) {
                    any_child_sat = true;
                    cats = r.cats;
                }
                any_sat = any_sat or r.has_any_satisfied;
            }
            return .{ .satisfied = any_child_sat, .has_any_satisfied = any_sat, .cats = cats };
        },
        .ordered => |children| {
            var prev_all_sat = true;
            var any_sat = false;
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = try checkOrderedSubtree(c, slots, idx, registry);
                if (r.has_any_satisfied and !prev_all_sat) {
                    return errors.MfaError.InvalidSessionState;
                }
                prev_all_sat = prev_all_sat and r.satisfied;
                any_sat = any_sat or r.has_any_satisfied;
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = prev_all_sat, .has_any_satisfied = any_sat, .cats = cats };
        },
        .threshold => |th| {
            var sat_count: u32 = 0;
            var any_sat = false;
            var cats = types.CategorySet{};
            for (th.nodes) |*c| {
                const r = try checkOrderedSubtree(c, slots, idx, registry);
                any_sat = any_sat or r.has_any_satisfied;
                if (r.satisfied) {
                    if (th.distinct_categories) {
                        const prev_bits = @as(u8, @bitCast(cats)) & 0x07;
                        const cur_bits = @as(u8, @bitCast(r.cats)) & 0x07;
                        if ((prev_bits & cur_bits) == 0 and cur_bits != 0) {
                            sat_count += 1;
                            cats = cats.merge(r.cats);
                        }
                    } else {
                        sat_count += 1;
                        cats = cats.merge(r.cats);
                    }
                }
            }
            return .{ .satisfied = sat_count >= th.k, .has_any_satisfied = any_sat, .cats = cats };
        },
    }
}

const SealCodecError = errors.MfaError || errors.InfraError;

fn mapWriteErr(e: crypto.CodecError) SealCodecError {
    return switch (e) {
        error.OutOfMemory => errors.InfraError.OutOfMemory,
        error.LengthOverflow => errors.MfaError.LimitExceeded,
        else => errors.InfraError.SealError,
    };
}

fn mapReadErr(e: crypto.CodecError) SealCodecError {
    return switch (e) {
        error.OutOfMemory => errors.InfraError.OutOfMemory,
        else => errors.MfaError.InvalidSessionState,
    };
}

fn writeLimits(w: *crypto.BinaryWriter, lim: types.SessionLimits) SealCodecError!void {
    w.writeInt(u64, lim.max_session_ttl_s) catch |e| return mapWriteErr(e);
    w.writeInt(u64, lim.max_grant_ttl_s) catch |e| return mapWriteErr(e);
    w.writeU8(lim.max_failed_verifications_per_session) catch |e| return mapWriteErr(e);
    w.writeU8(lim.max_challenges_per_leaf) catch |e| return mapWriteErr(e);
    w.writeU8(lim.max_challenge_rounds_per_leaf) catch |e| return mapWriteErr(e);
    w.writeU8(lim.max_active_challenges) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_proof_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_request_ctx_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_scope_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_derived_ctx_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_claims_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_challenge_state_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_state_update_len)) catch |e| return mapWriteErr(e);
    w.writeInt(u64, @intCast(lim.max_sealed_blob_len)) catch |e| return mapWriteErr(e);
    w.writeU8(lim.max_conflict_retries) catch |e| return mapWriteErr(e);
    w.writeInt(u32, lim.clock_skew_tolerance_s) catch |e| return mapWriteErr(e);
}

fn readLimits(r: *crypto.BinaryReader) errors.MfaError!types.SessionLimits {
    const max_session_ttl_s = r.readInt(u64) catch return errors.MfaError.InvalidSessionState;
    const max_grant_ttl_s = r.readInt(u64) catch return errors.MfaError.InvalidSessionState;
    const max_failed_verifications_per_session = r.readU8() catch return errors.MfaError.InvalidSessionState;
    const max_challenges_per_leaf = r.readU8() catch return errors.MfaError.InvalidSessionState;
    const max_challenge_rounds_per_leaf = r.readU8() catch return errors.MfaError.InvalidSessionState;
    const max_active_challenges = r.readU8() catch return errors.MfaError.InvalidSessionState;
    const max_proof_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_request_ctx_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_scope_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_derived_ctx_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_claims_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_challenge_state_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_state_update_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_sealed_blob_len = std.math.cast(usize, r.readInt(u64) catch return errors.MfaError.InvalidSessionState) orelse return errors.MfaError.InvalidSessionState;
    const max_conflict_retries = r.readU8() catch return errors.MfaError.InvalidSessionState;
    const clock_skew_tolerance_s = r.readInt(u32) catch return errors.MfaError.InvalidSessionState;
    return .{
        .max_session_ttl_s = max_session_ttl_s,
        .max_grant_ttl_s = max_grant_ttl_s,
        .max_failed_verifications_per_session = max_failed_verifications_per_session,
        .max_challenges_per_leaf = max_challenges_per_leaf,
        .max_challenge_rounds_per_leaf = max_challenge_rounds_per_leaf,
        .max_active_challenges = max_active_challenges,
        .max_proof_len = max_proof_len,
        .max_request_ctx_len = max_request_ctx_len,
        .max_scope_len = max_scope_len,
        .max_derived_ctx_len = max_derived_ctx_len,
        .max_claims_len = max_claims_len,
        .max_challenge_state_len = max_challenge_state_len,
        .max_state_update_len = max_state_update_len,
        .max_sealed_blob_len = max_sealed_blob_len,
        .max_conflict_retries = max_conflict_retries,
        .clock_skew_tolerance_s = clock_skew_tolerance_s,
    };
}

test "SessionState seal and open round-trip with AAD mismatch check" {
    const DummyRand = struct {
        fn bytes(_: *anyopaque, out: []u8) ports.RandomPort.RandomError!void {
            @memset(out, 0x33);
        }
        const vtable = ports.RandomPort.VTable{ .bytes = bytes };
        fn port(self: *@This()) ports.RandomPort {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
    const DummySealer = struct {
        fn seal(_: *anyopaque, alloc: std.mem.Allocator, _: ports.RandomPort, pt: []const u8, aad: []const u8) ports.StateSealer.SealerError![]u8 {
            var out = alloc.alloc(u8, 4 + aad.len + pt.len) catch return error.OutOfMemory;
            std.mem.writeInt(u32, out[0..4], @intCast(aad.len), .little);
            @memcpy(out[4 .. 4 + aad.len], aad);
            @memcpy(out[4 + aad.len ..], pt);
            return out;
        }
        fn open(_: *anyopaque, alloc: std.mem.Allocator, ct: []const u8, aad: []const u8) ports.StateSealer.SealerError![]u8 {
            if (ct.len < 4) return error.OpenFailed;
            const aad_len = std.mem.readInt(u32, ct[0..4], .little);
            if (4 + aad_len > ct.len) return error.OpenFailed;
            if (!std.mem.eql(u8, ct[4 .. 4 + aad_len], aad)) return error.OpenFailed;
            return alloc.dupe(u8, ct[4 + aad_len ..]) catch return error.OutOfMemory;
        }
        const vtable = ports.StateSealer.VTable{ .seal = seal, .open = open };
        fn port(self: *@This()) ports.StateSealer {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };

    var rnd = DummyRand{};
    var sealer = DummySealer{};
    const alloc = std.testing.allocator;
    const slots = try alloc.alloc(LeafSlot, 1);
    slots[0] = .{
        .factor_id = try alloc.dupe(u8, "pwd"),
        .output = .{ .factor_id = try alloc.dupe(u8, "pwd") },
    };

    var st = SessionState{
        .session_id = try alloc.dupe(u8, "sess-1"),
        .subject_id = try alloc.dupe(u8, "user-1"),
        .action_scope = try alloc.dupe(u8, "login"),
        .policy_fingerprint = @splat(0x11),
        .issued_at = 100,
        .last_activity_at = 100,
        .expires_at = 700,
        .leaf_slots = slots,
    };
    defer st.deinit(alloc, alloc);

    const blob = try st.seal(alloc, alloc, rnd.port(), sealer.port(), "");
    defer alloc.free(blob);

    var opened = try SessionState.open(alloc, alloc, sealer.port(), blob, .{
        .session_id = "sess-1",
        .policy_fingerprint = @splat(0x11),
        .expected_version = 1,
    }, 64 * 1024);
    defer opened.deinit(alloc, alloc);

    try std.testing.expectEqualStrings("user-1", opened.subject_id);
    try std.testing.expectError(errors.MfaError.InvalidSessionState, SessionState.open(alloc, alloc, sealer.port(), blob, .{
        .session_id = "sess-2",
        .policy_fingerprint = @splat(0x11),
        .expected_version = 1,
    }, 64 * 1024));
}
