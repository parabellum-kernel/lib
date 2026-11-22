const std = @import("std");
const primitives = @import("primitives.zig");
const types = @import("types.zig");
const ports = @import("ports.zig");
const errors = @import("errors.zig");
const registry_mod = @import("registry.zig");
const policy = @import("policy.zig");
const fingerprint = @import("fingerprint.zig");
const session = @import("session.zig");

pub const EngineEnv = struct {
    allocator: std.mem.Allocator,
    secret_allocator: ?std.mem.Allocator = null,
    random: ports.RandomPort,
    registry: *const registry_mod.FactorRegistry,
    hash: ports.HashPort,
    tracker: ports.AttemptTracker,
    store: ports.FactorStateStore,
    sealer: ?ports.StateSealer = null,
    audit: ?ports.AuditSink = null,
    admission: ?ports.AdmissionPolicy = null,
    visibility: ?ports.EnrollmentVisibilityPolicy = null,
    migration: ?ports.PolicyMigrationHook = null,
    allow_unlisted_hash: bool = false,
};

pub const CallMeta = struct {
    now_unix_s: i64,
    binding: []const u8 = "",
    source_key: ?[]const u8 = null,
    request_ctx: ?[]const u8 = null,
};

pub const StartOptions = struct {
    ttl_s: u64 = 300,
    limits: types.SessionLimits = .{},
    assurance: types.AssurancePolicy = .{},
    binding_mode: types.BindingMode = .bound,
    outcome_class: types.OutcomeClass = .terminal,
    enrollment_mode: types.EnrollmentMode = .lazy_on_challenge,
};

pub const StartOutcome = union(enum) {
    started: session.SessionState,
    rate_limited: u64,
    rejected: void,

    pub fn deinit(self: *StartOutcome, allocator: std.mem.Allocator, secret_allocator: ?std.mem.Allocator) void {
        switch (self.*) {
            .started => |*s| s.deinit(allocator, secret_allocator),
            else => {},
        }
    }
};

pub const ChallengeOutcome = union(enum) {
    challenge: []u8,
    not_applicable: void,
    rate_limited: u64,

    pub fn deinit(self: *ChallengeOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .challenge => |c| allocator.free(c),
            else => {},
        }
    }
};

pub const EligibleFactorsResult = struct {
    factors: [][]const u8,
    visibility: types.EnrollmentVisibilityMode,

    pub fn deinit(self: *EligibleFactorsResult, allocator: std.mem.Allocator) void {
        allocator.free(self.factors);
    }
};

pub fn validateEnv(env: EngineEnv) errors.MfaError!void {
    if (env.allow_unlisted_hash) return;
    const alg = env.hash.algorithmId();
    if (!std.mem.eql(u8, alg, "sha256") and
        !std.mem.eql(u8, alg, "sha3-256") and
        !std.mem.eql(u8, alg, "blake3"))
    {
        return errors.MfaError.InvalidPolicy;
    }
}

pub fn verifyBinding(env: EngineEnv, state: *const session.SessionState, meta: CallMeta) (errors.MfaError || errors.InfraError)!void {
    if (state.binding_mode == .unbound) return;
    const expected = state.binding_hash orelse return errors.MfaError.SessionBindingMismatch;
    const mismatch = blk: {
        if (meta.binding.len == 0) break :blk true;
        const actual = fingerprint.bindingHash(env.hash, meta.binding);
        break :blk !primitives.ctEql32(&actual, &expected);
    };
    if (mismatch) {
        const res = env.tracker.reserve(.session_access, .{
            .subject_id = "",
            .session_id = state.session_id,
            .source_key = meta.source_key,
        }, meta.now_unix_s) catch return errors.InfraError.TrackerError;
        switch (res) {
            .granted => |r| {
                env.tracker.settle(r, .rejected, meta.now_unix_s) catch return errors.InfraError.TrackerError;
            },
            .locked_out => {},
        }
        if (env.audit) |a| {
            a.emit(.{
                .kind = .binding_mismatch,
                .now_unix_s = meta.now_unix_s,
                .subject_id = state.subject_id,
                .session_id = state.session_id,
                .source_key = meta.source_key,
            });
        }
        return errors.MfaError.SessionBindingMismatch;
    }
}

pub fn advanceClock(state: *const session.SessionState, now_unix_s: i64) errors.MfaError!i64 {
    const skew: i64 = @intCast(state.limits.clock_skew_tolerance_s);
    if (now_unix_s + skew < state.last_activity_at) {
        return errors.MfaError.ClockSkewDetected;
    }
    return @max(state.last_activity_at, now_unix_s);
}

pub const ActivePolicy = struct {
    chain: policy.SecurityChain,
    registry: *const registry_mod.FactorRegistry,
    outcome_class: types.OutcomeClass,
    binding_mode: types.BindingMode,
    assurance: types.AssurancePolicy,
};

pub fn resolveActivePolicy(
    env: EngineEnv,
    state: *const session.SessionState,
    chain: policy.SecurityChain,
    effective_now: i64,
) (errors.MfaError || errors.InfraError)!ActivePolicy {
    const fp = fingerprint.policyFingerprint(env.allocator, env.hash, env.registry, chain, .{
        .outcome_class = state.outcome_class,
        .binding_mode = state.binding_mode,
        .assurance = state.assurance,
    }) catch return errors.InfraError.OutOfMemory;

    if (primitives.ctEql32(&fp, &state.policy_fingerprint)) {
        return .{
            .chain = chain,
            .registry = env.registry,
            .outcome_class = state.outcome_class,
            .binding_mode = state.binding_mode,
            .assurance = state.assurance,
        };
    }

    if (env.migration) |mig| {
        if (mig.resolveLegacy(state.policy_fingerprint, state.action_scope, effective_now)) |res| {
            if (effective_now >= res.sunset_unix_s) {
                return errors.MfaError.PolicyMismatch;
            }
            if (res.outcome_class != state.outcome_class or res.binding_mode != state.binding_mode) {
                return errors.MfaError.PolicyMismatch;
            }
            if (!std.mem.eql(u8, res.chain.action_scope, state.action_scope)) {
                return errors.MfaError.PolicyMismatch;
            }
            const active_reg = res.legacy_registry orelse env.registry;
            const legacy_fp = fingerprint.policyFingerprint(env.allocator, env.hash, active_reg, res.chain.*, .{
                .outcome_class = res.outcome_class,
                .binding_mode = res.binding_mode,
                .assurance = res.assurance,
            }) catch return errors.InfraError.OutOfMemory;
            if (!primitives.ctEql32(&legacy_fp, &state.policy_fingerprint)) {
                return errors.MfaError.PolicyMismatch;
            }
            try policy.validatePolicy(
                .{ .registry = active_reg, .store = env.store },
                res.chain.*,
                res.assurance,
                state.enrollment_mode,
                state.limits,
            );
            return .{
                .chain = res.chain.*,
                .registry = active_reg,
                .outcome_class = res.outcome_class,
                .binding_mode = res.binding_mode,
                .assurance = res.assurance,
            };
        }
    }
    return errors.MfaError.PolicyMismatch;
}

pub fn deriveTranscript(
    hash: ports.HashPort,
    fp: [32]u8,
    session_id: []const u8,
    scope: []const u8,
    subject_id: []const u8,
    factor_id: []const u8,
    nonce: [32]u8,
    binding_hash: ?[32]u8,
) [32]u8 {
    const alg = hash.algorithmId();
    var alg_len: [4]u8 = undefined;
    var sid_len: [4]u8 = undefined;
    var scope_len: [4]u8 = undefined;
    var sub_len: [4]u8 = undefined;
    var fid_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &alg_len, @intCast(alg.len), .little);
    std.mem.writeInt(u32, &sid_len, @intCast(session_id.len), .little);
    std.mem.writeInt(u32, &scope_len, @intCast(scope.len), .little);
    std.mem.writeInt(u32, &sub_len, @intCast(subject_id.len), .little);
    std.mem.writeInt(u32, &fid_len, @intCast(factor_id.len), .little);
    const zero_bh: [32]u8 = @splat(0);
    const bh_slice: []const u8 = if (binding_hash) |*bh| bh else &zero_bh;

    return hash.hash(&.{
        "parabellum_mfa/transcript/v6\x00",
        &alg_len,
        alg,
        &fp,
        &sid_len,
        session_id,
        &scope_len,
        scope,
        &sub_len,
        subject_id,
        &fid_len,
        factor_id,
        &nonce,
        bh_slice,
    });
}

fn collectLeaves(node: policy.PolicyNode, list: *std.ArrayList([]const u8), alloc: std.mem.Allocator) !void {
    switch (node) {
        .leaf => |l| try list.append(alloc, l.factor_id),
        .all_of, .batch_all_of, .any_of, .ordered => |children| {
            for (children) |c| try collectLeaves(c, list, alloc);
        },
        .threshold => |th| {
            for (th.nodes) |c| try collectLeaves(c, list, alloc);
        },
    }
}

pub fn startChain(
    env: EngineEnv,
    subject_id: []const u8,
    chain: policy.SecurityChain,
    meta: CallMeta,
    opts: StartOptions,
) (errors.MfaError || errors.InfraError)!StartOutcome {
    try validateEnv(env);
    if (subject_id.len == 0) return errors.MfaError.InvalidPolicy;
    if (meta.request_ctx) |rc| {
        if (rc.len > opts.limits.max_request_ctx_len) return errors.MfaError.LimitExceeded;
    }
    if (policy.isReservedScope(chain.action_scope) and opts.outcome_class != .terminal) {
        return errors.MfaError.InvalidPolicy;
    }
    if (opts.outcome_class == .intermediate and opts.binding_mode == .unbound) {
        return errors.MfaError.InvalidPolicy;
    }
    if (opts.ttl_s == 0 or opts.ttl_s > opts.limits.max_session_ttl_s) {
        return errors.MfaError.LimitExceeded;
    }
    const ttl_i64 = std.math.cast(i64, opts.ttl_s) orelse return errors.MfaError.LimitExceeded;
    const expires_at = std.math.add(i64, meta.now_unix_s, ttl_i64) catch return errors.MfaError.LimitExceeded;

    if (opts.binding_mode == .bound and meta.binding.len < 16) {
        return errors.MfaError.WeakBinding;
    }

    try policy.validatePolicy(.{ .registry = env.registry, .store = env.store }, chain, opts.assurance, opts.enrollment_mode, opts.limits);

    if (env.admission) |adm| {
        const dec = adm.evaluate(.{
            .phase = .session_start,
            .action_scope = chain.action_scope,
            .subject_id = subject_id,
            .source_key = meta.source_key,
            .request_ctx = meta.request_ctx,
            .now_unix_s = meta.now_unix_s,
        }) catch return errors.InfraError.AdmissionError;
        switch (dec) {
            .allow => {},
            .defer_retry => |d| return .{ .rate_limited = d.retry_after_s },
            .deny => return .rejected,
        }
    }

    var sid_bytes: [16]u8 = undefined;
    env.random.bytes(&sid_bytes) catch return errors.InfraError.EntropyError;
    const sid_hex = std.fmt.bytesToHex(sid_bytes, .lower);

    const res_dec = env.tracker.reserve(.session_start, .{
        .subject_id = subject_id,
        .source_key = meta.source_key,
    }, meta.now_unix_s) catch return errors.InfraError.TrackerError;

    const reservation = switch (res_dec) {
        .granted => |r| r,
        .locked_out => |d| return .{ .rate_limited = d.retry_after_s },
    };
    var settled = false;
    errdefer if (!settled) {
        env.tracker.settle(reservation, .released, meta.now_unix_s) catch {};
    };

    var leaf_ids: std.ArrayList([]const u8) = .empty;
    defer leaf_ids.deinit(env.allocator);
    collectLeaves(chain.root, &leaf_ids, env.allocator) catch return errors.InfraError.OutOfMemory;

    if (opts.enrollment_mode == .eager_validate) {
        var any_enrolled = false;
        for (leaf_ids.items) |fid| {
            if (env.registry.getEntry(fid)) |entry| {
                const ok = entry.verifier.isEnrolled(subject_id) catch |e| switch (e) {
                    error.OutOfMemory => return errors.InfraError.OutOfMemory,
                    error.VerifierIoError => return errors.InfraError.VerifierIoError,
                };
                if (ok) any_enrolled = true;
            }
        }
        if (!any_enrolled) {
            settled = true;
            env.tracker.settle(reservation, .released, meta.now_unix_s) catch return errors.InfraError.TrackerError;
            return errors.MfaError.PolicyUnsatisfiable;
        }
    }

    const slots = env.allocator.alloc(session.LeafSlot, leaf_ids.items.len) catch return errors.InfraError.OutOfMemory;
    var init_count: usize = 0;
    errdefer {
        for (slots[0..init_count]) |*s| s.deinit(env.allocator, env.secret_allocator);
        env.allocator.free(slots);
    }

    for (leaf_ids.items, 0..) |fid, i| {
        const fid_copy = env.allocator.dupe(u8, fid) catch return errors.InfraError.OutOfMemory;
        errdefer env.allocator.free(fid_copy);
        const out_fid_copy = env.allocator.dupe(u8, fid) catch return errors.InfraError.OutOfMemory;
        slots[i] = .{
            .factor_id = fid_copy,
            .output = .{ .factor_id = out_fid_copy },
        };
        init_count += 1;
    }

    const fp = fingerprint.policyFingerprint(env.allocator, env.hash, env.registry, chain, .{
        .outcome_class = opts.outcome_class,
        .binding_mode = opts.binding_mode,
        .assurance = opts.assurance,
    }) catch return errors.InfraError.OutOfMemory;

    var binding_hash: ?[32]u8 = null;
    if (opts.binding_mode == .bound) {
        binding_hash = fingerprint.bindingHash(env.hash, meta.binding);
    }

    const state = session.SessionState{
        .session_id = env.allocator.dupe(u8, &sid_hex) catch return errors.InfraError.OutOfMemory,
        .subject_id = env.allocator.dupe(u8, subject_id) catch return errors.InfraError.OutOfMemory,
        .action_scope = env.allocator.dupe(u8, chain.action_scope) catch return errors.InfraError.OutOfMemory,
        .policy_fingerprint = fp,
        .status = .active,
        .limits = opts.limits,
        .assurance = opts.assurance,
        .binding_mode = opts.binding_mode,
        .binding_hash = binding_hash,
        .outcome_class = opts.outcome_class,
        .enrollment_mode = opts.enrollment_mode,
        .issued_at = meta.now_unix_s,
        .last_activity_at = meta.now_unix_s,
        .expires_at = expires_at,
        .leaf_slots = slots,
    };

    settled = true;
    env.tracker.settle(reservation, .session_started, meta.now_unix_s) catch return errors.InfraError.TrackerError;
    if (env.audit) |a| {
        a.emit(.{
            .kind = .session_started,
            .now_unix_s = meta.now_unix_s,
            .subject_id = state.subject_id,
            .session_id = state.session_id,
            .source_key = meta.source_key,
        });
    }

    return .{ .started = state };
}

fn findSlot(state: *session.SessionState, factor_id: []const u8) ?*session.LeafSlot {
    for (state.leaf_slots) |*slot| {
        if (std.mem.eql(u8, slot.factor_id, factor_id)) return slot;
    }
    return null;
}

const LeafEligibility = enum {
    eligible,
    not_ready,
    not_needed,
    not_found,
};

const EligibilityEval = struct {
    satisfied: bool,
    cats: types.CategorySet = .{},
};

fn findLeafInSubtree(
    node: *const policy.PolicyNode,
    slots: []const session.LeafSlot,
    idx: *usize,
    target_id: []const u8,
    registry: *const registry_mod.FactorRegistry,
    parent_pruned: bool,
    parent_blocked: bool,
    result: *LeafEligibility,
) EligibilityEval {
    switch (node.*) {
        .leaf => |l| {
            const sat = slots[idx.*].phase == .satisfied;
            idx.* += 1;
            if (std.mem.eql(u8, l.factor_id, target_id)) {
                if (parent_pruned) {
                    result.* = .not_needed;
                } else if (parent_blocked) {
                    result.* = .not_ready;
                } else {
                    result.* = .eligible;
                }
            }
            const cats = if (sat) (if (registry.get(l.factor_id)) |d| d.categories else types.CategorySet{}) else types.CategorySet{};
            return .{ .satisfied = sat, .cats = cats };
        },
        .all_of, .batch_all_of => |children| {
            var all_sat = true;
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = findLeafInSubtree(c, slots, idx, target_id, registry, parent_pruned, parent_blocked, result);
                all_sat = all_sat and r.satisfied;
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = all_sat, .cats = cats };
        },
        .any_of => |children| {
            // Two-pass or check if already satisfied? Wait: we must advance idx properly, so check subtree satisfaction first or track!
            // Actually, if we check if any_of is already satisfied before recursing, we don't advance idx twice if we use a separate pure satisfaction check.
            var save_idx = idx.*;
            const already_sat = isSubtreeSatisfied(node, slots, &save_idx, registry);
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = findLeafInSubtree(c, slots, idx, target_id, registry, parent_pruned or already_sat, parent_blocked, result);
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = already_sat, .cats = cats };
        },
        .ordered => |children| {
            var prev_sat = true;
            var cats = types.CategorySet{};
            for (children) |*c| {
                const r = findLeafInSubtree(c, slots, idx, target_id, registry, parent_pruned, parent_blocked or !prev_sat, result);
                prev_sat = prev_sat and r.satisfied;
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = prev_sat, .cats = cats };
        },
        .threshold => |th| {
            var save_idx = idx.*;
            const already_sat = isSubtreeSatisfied(node, slots, &save_idx, registry);
            var cats = types.CategorySet{};
            for (th.nodes) |*c| {
                const r = findLeafInSubtree(c, slots, idx, target_id, registry, parent_pruned or already_sat, parent_blocked, result);
                if (r.satisfied) cats = cats.merge(r.cats);
            }
            return .{ .satisfied = already_sat, .cats = cats };
        },
    }
}

fn isSubtreeSatisfied(
    node: *const policy.PolicyNode,
    slots: []const session.LeafSlot,
    idx: *usize,
    registry: *const registry_mod.FactorRegistry,
) bool {
    return switch (node.*) {
        .leaf => blk: {
            const sat = slots[idx.*].phase == .satisfied;
            idx.* += 1;
            break :blk sat;
        },
        .all_of, .batch_all_of, .ordered => |children| blk: {
            var all_sat = true;
            for (children) |*c| {
                if (!isSubtreeSatisfied(c, slots, idx, registry)) all_sat = false;
            }
            break :blk all_sat;
        },
        .any_of => |children| blk: {
            var any_sat = false;
            for (children) |*c| {
                if (isSubtreeSatisfied(c, slots, idx, registry)) any_sat = true;
            }
            break :blk any_sat;
        },
        .threshold => |th| blk: {
            var count: u32 = 0;
            var cats = types.CategorySet{};
            for (th.nodes) |*c| {
                const start_i = idx.*;
                const sat = isSubtreeSatisfied(c, slots, idx, registry);
                if (sat) {
                    if (th.distinct_categories) {
                        var c_cats = types.CategorySet{};
                        for (slots[start_i..idx.*]) |s| {
                            if (s.phase == .satisfied) {
                                if (registry.get(s.factor_id)) |d| c_cats = c_cats.merge(d.categories);
                            }
                        }
                        const prev_bits = @as(u8, @bitCast(cats)) & 0x07;
                        const cur_bits = @as(u8, @bitCast(c_cats)) & 0x07;
                        if ((prev_bits & cur_bits) == 0 and cur_bits != 0) {
                            count += 1;
                            cats = cats.merge(c_cats);
                        }
                    } else {
                        count += 1;
                    }
                }
            }
            break :blk count >= th.k;
        },
    };
}

pub fn checkLeafEligibility(
    root: *const policy.PolicyNode,
    slots: []const session.LeafSlot,
    factor_id: []const u8,
    registry: *const registry_mod.FactorRegistry,
) LeafEligibility {
    var idx: usize = 0;
    var res: LeafEligibility = .not_found;
    _ = findLeafInSubtree(root, slots, &idx, factor_id, registry, false, false, &res);
    return res;
}

fn findLeafNode(node: *const policy.PolicyNode, factor_id: []const u8) ?policy.LeafNode {
    return switch (node.*) {
        .leaf => |l| if (std.mem.eql(u8, l.factor_id, factor_id)) l else null,
        .all_of, .batch_all_of, .any_of, .ordered => |children| blk: {
            for (children) |*c| {
                if (findLeafNode(c, factor_id)) |found| break :blk found;
            }
            break :blk null;
        },
        .threshold => |th| blk: {
            for (th.nodes) |*c| {
                if (findLeafNode(c, factor_id)) |found| break :blk found;
            }
            break :blk null;
        },
    };
}

pub fn collectDerivedContexts(
    allocator: std.mem.Allocator,
    state: *const session.SessionState,
    chain: policy.SecurityChain,
    factor_id: []const u8,
) errors.InfraError![]ports.FactorVerifier.DerivedContext {
    const leaf = findLeafNode(&chain.root, factor_id) orelse return &.{};
    if (leaf.reads_ctx_from.len == 0) return &.{};

    var list: std.ArrayList(ports.FactorVerifier.DerivedContext) = .empty;
    errdefer list.deinit(allocator);

    for (leaf.reads_ctx_from) |dep| {
        for (state.leaf_slots) |slot| {
            if (std.mem.eql(u8, slot.factor_id, dep.factor_id) and slot.phase == .satisfied) {
                if (slot.output.derived_ctx) |dc| {
                    list.append(allocator, .{
                        .factor_id = dep.factor_id,
                        .bytes = dc,
                    }) catch return errors.InfraError.OutOfMemory;
                }
                break;
            }
        }
    }
    return list.toOwnedSlice(allocator) catch return errors.InfraError.OutOfMemory;
}

pub fn wipeAllChallenges(sec: std.mem.Allocator, state: *session.SessionState) void {
    for (state.leaf_slots) |*slot| {
        if (slot.phase == .challenged) {
            if (slot.phase.challenged.challenge_state) |cs| {
                primitives.wipe(cs);
                sec.free(cs);
            }
            slot.phase = .idle;
        }
    }
}

pub fn requestChallenge(
    env: EngineEnv,
    state: *session.SessionState,
    chain: policy.SecurityChain,
    meta: CallMeta,
    factor_id: []const u8,
) (errors.MfaError || errors.InfraError)!ChallengeOutcome {
    try validateEnv(env);
    if (meta.request_ctx) |rc| {
        if (rc.len > state.limits.max_request_ctx_len) return errors.MfaError.LimitExceeded;
    }
    try verifyBinding(env, state, meta);
    const effective_now = try advanceClock(state, meta.now_unix_s);
    const active = try resolveActivePolicy(env, state, chain, effective_now);
    try session.checkInvariants(state, active.chain, active.registry);

    if (state.status == .invalidated) return errors.MfaError.SessionInvalidated;
    if (state.status == .expired) return errors.MfaError.SessionExpired;
    if (state.status != .active) return errors.MfaError.SessionCompleted;
    if (effective_now >= state.expires_at) {
        state.status = .expired;
        return errors.MfaError.SessionExpired;
    }

    const slot = findSlot(state, factor_id) orelse return errors.MfaError.FactorNotInPolicy;
    if (slot.phase == .satisfied) return errors.MfaError.FactorAlreadySatisfied;
    switch (checkLeafEligibility(&active.chain.root, state.leaf_slots, factor_id, active.registry)) {
        .eligible => {},
        .not_ready => return errors.MfaError.FactorNotReady,
        .not_needed => return errors.MfaError.FactorNotNeeded,
        .not_found => return errors.MfaError.FactorNotInPolicy,
    }
    if (slot.challenges_issued >= state.limits.max_challenges_per_leaf) {
        wipeAllChallenges(env.secret_allocator orelse env.allocator, state);
        state.status = .invalidated;
        state.last_activity_at = effective_now;
        state.version += 1;
        if (env.audit) |a| {
            a.emit(.{
                .kind = .session_invalidated,
                .now_unix_s = effective_now,
                .subject_id = state.subject_id,
                .session_id = state.session_id,
                .factor_id = factor_id,
                .source_key = meta.source_key,
            });
        }
        return errors.MfaError.LimitExceeded;
    }

    const entry = active.registry.getEntry(factor_id) orelse return errors.MfaError.FactorNotFound;
    if (!entry.descriptor.requires_challenge) return .not_applicable;

    if (env.admission) |adm| {
        const dec = adm.evaluate(.{
            .phase = .challenge_issue,
            .action_scope = state.action_scope,
            .subject_id = state.subject_id,
            .factor_id = factor_id,
            .factor_type = entry.descriptor.factor_type,
            .source_key = meta.source_key,
            .request_ctx = meta.request_ctx,
            .now_unix_s = effective_now,
        }) catch return errors.InfraError.AdmissionError;
        switch (dec) {
            .allow => {},
            .defer_retry => |d| return .{ .rate_limited = d.retry_after_s },
            .deny => return errors.MfaError.AdmissionDenied,
        }
    }

    const res_dec = env.tracker.reserve(.challenge, .{
        .subject_id = state.subject_id,
        .factor_id = factor_id,
        .session_id = state.session_id,
        .source_key = meta.source_key,
    }, effective_now) catch return errors.InfraError.TrackerError;
    const reservation = switch (res_dec) {
        .granted => |r| r,
        .locked_out => |d| return .{ .rate_limited = d.retry_after_s },
    };
    var settled = false;
    errdefer if (!settled) {
        env.tracker.settle(reservation, .infra_error, effective_now) catch {};
    };

    var nonce: [32]u8 = undefined;
    env.random.bytes(&nonce) catch return errors.InfraError.EntropyError;

    const transcript = deriveTranscript(
        env.hash,
        state.policy_fingerprint,
        state.session_id,
        state.action_scope,
        state.subject_id,
        factor_id,
        nonce,
        state.binding_hash,
    );

    const derived_ctxs = try collectDerivedContexts(env.allocator, state, active.chain, factor_id);
    defer if (derived_ctxs.len > 0) env.allocator.free(derived_ctxs);

    const emission = entry.verifier.issueChallenge(.{
        .allocator = env.allocator,
        .secret_allocator = env.secret_allocator orelse env.allocator,
        .random = env.random,
        .session_id = state.session_id,
        .subject_id = state.subject_id,
        .action_scope = state.action_scope,
        .factor_id = factor_id,
        .factor_challenge_nonce = nonce,
        .transcript = transcript,
        .enrollment_mode = state.enrollment_mode,
        .now_unix_s = effective_now,
        .request_ctx = meta.request_ctx,
        .derived_contexts = derived_ctxs,
    }) catch |e| switch (e) {
        error.OutOfMemory => return errors.InfraError.OutOfMemory,
        error.VerifierIoError => return errors.InfraError.VerifierIoError,
    };

    switch (emission) {
        .not_applicable => {
            settled = true;
            env.tracker.settle(reservation, .released, effective_now) catch return errors.InfraError.TrackerError;
            return .not_applicable;
        },
        .not_enrolled => {
            settled = true;
            env.tracker.settle(reservation, .released, effective_now) catch return errors.InfraError.TrackerError;
            return if (state.enrollment_mode == .eager_validate)
                errors.MfaError.FactorNotEnrolled
            else
                errors.InfraError.VerifierProtocolViolation;
        },
        .challenge => |ch| {
            const sec = env.secret_allocator orelse env.allocator;
            if (ch.payload.len > state.limits.max_proof_len or
                (ch.challenge_state != null and ch.challenge_state.?.len > state.limits.max_challenge_state_len))
            {
                env.allocator.free(ch.payload);
                if (ch.challenge_state) |cs| {
                    primitives.wipe(cs);
                    sec.free(cs);
                }
                return errors.InfraError.VerifierProtocolViolation;
            }

            settled = true;
            env.tracker.settle(reservation, .challenge_issued, effective_now) catch |err| {
                env.allocator.free(ch.payload);
                if (ch.challenge_state) |cs| {
                    primitives.wipe(cs);
                    sec.free(cs);
                }
                return switch (err) {
                    error.OutOfMemory => errors.InfraError.OutOfMemory,
                    else => errors.InfraError.TrackerError,
                };
            };

            // FIFO eviction if at max_active_challenges (when slot was idle)
            if (slot.phase == .idle) {
                var active_count: u16 = 0;
                var oldest_slot: ?*session.LeafSlot = null;
                var oldest_seq: u64 = std.math.maxInt(u64);
                for (state.leaf_slots) |*s| {
                    switch (s.phase) {
                        .challenged => |cd| {
                            active_count += 1;
                            if (cd.active_seq < oldest_seq) {
                                oldest_seq = cd.active_seq;
                                oldest_slot = s;
                            }
                        },
                        else => {},
                    }
                }
                if (active_count >= state.limits.max_active_challenges) {
                    if (oldest_slot) |os| {
                        if (os.phase == .challenged) {
                            if (os.phase.challenged.challenge_state) |cs| {
                                primitives.wipe(cs);
                                sec.free(cs);
                            }
                        }
                        os.phase = .idle;
                    }
                }
            } else if (slot.phase == .challenged) {
                if (slot.phase.challenged.challenge_state) |cs| {
                    primitives.wipe(cs);
                    sec.free(cs);
                }
            }

            const chal_exp: i64 = if (ch.ttl_s) |t| blk: {
                const t_i64 = std.math.cast(i64, t) orelse break :blk state.expires_at;
                const sum = std.math.add(i64, effective_now, t_i64) catch break :blk state.expires_at;
                break :blk @min(state.expires_at, sum);
            } else state.expires_at;

            slot.challenges_issued += 1;
            slot.phase = .{ .challenged = .{
                .factor_challenge_nonce = nonce,
                .issued_at = effective_now,
                .expires_at = chal_exp,
                .challenge_state = ch.challenge_state,
                .decoy = ch.decoy,
                .active_seq = state.next_active_seq,
            } };
            state.next_active_seq += 1;
            state.last_activity_at = effective_now;
            state.version += 1;

            if (env.audit) |a| {
                a.emit(.{
                    .kind = .challenge_issued,
                    .now_unix_s = effective_now,
                    .subject_id = state.subject_id,
                    .session_id = state.session_id,
                    .factor_id = factor_id,
                    .source_key = meta.source_key,
                });
            }

            return .{ .challenge = ch.payload };
        },
    }
}

pub fn invalidateSession(
    env: EngineEnv,
    state: *session.SessionState,
    chain: policy.SecurityChain,
    meta: CallMeta,
) (errors.MfaError || errors.InfraError)!void {
    try validateEnv(env);
    try verifyBinding(env, state, meta);
    const effective_now = try advanceClock(state, meta.now_unix_s);
    const active = try resolveActivePolicy(env, state, chain, effective_now);
    try session.checkInvariants(state, active.chain, active.registry);

    wipeAllChallenges(env.secret_allocator orelse env.allocator, state);
    state.status = .invalidated;
    state.last_activity_at = effective_now;
    state.version += 1;

    if (env.audit) |a| {
        a.emit(.{
            .kind = .session_invalidated,
            .now_unix_s = effective_now,
            .subject_id = state.subject_id,
            .session_id = state.session_id,
            .source_key = meta.source_key,
        });
    }
}

pub fn eligibleFactors(
    env: EngineEnv,
    state: *const session.SessionState,
    chain: policy.SecurityChain,
    meta: CallMeta,
) (errors.MfaError || errors.InfraError)!EligibleFactorsResult {
    try validateEnv(env);
    try verifyBinding(env, state, meta);
    const effective_now = try advanceClock(state, meta.now_unix_s);
    const active = try resolveActivePolicy(env, state, chain, effective_now);
    try session.checkInvariants(state, active.chain, active.registry);

    var vis: types.EnrollmentVisibilityMode = .structural_only;
    if (state.enrollment_mode == .eager_validate) {
        vis = .enrolled_filtered;
    } else if (env.visibility) |v| {
        var sat: u8 = 0;
        var sat_cats: u8 = 0;
        for (state.leaf_slots) |s| {
            if (s.phase == .satisfied) {
                sat += 1;
                if (active.registry.get(s.factor_id)) |d| {
                    sat_cats |= @as(u8, @bitCast(d.categories)) & 0x07;
                }
            }
        }
        if (v.canRevealEnrolled(.{
            .action_scope = state.action_scope,
            .subject_id = state.subject_id,
            .satisfied_categories = sat_cats,
            .satisfied_leaf_count = sat,
            .is_bound = state.binding_mode == .bound,
            .now_unix_s = effective_now,
        }, meta.request_ctx)) {
            vis = .enrolled_filtered;
        }
    }

    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(env.allocator);

    for (state.leaf_slots) |slot| {
        if (slot.phase == .satisfied) continue;
        if (checkLeafEligibility(&active.chain.root, state.leaf_slots, slot.factor_id, active.registry) != .eligible) {
            continue;
        }
        if (vis == .enrolled_filtered) {
            if (active.registry.getEntry(slot.factor_id)) |entry| {
                const ok = entry.verifier.isEnrolled(state.subject_id) catch |e| switch (e) {
                    error.OutOfMemory => return errors.InfraError.OutOfMemory,
                    error.VerifierIoError => return errors.InfraError.VerifierIoError,
                };
                if (!ok) continue;
            }
        }
        list.append(env.allocator, slot.factor_id) catch return errors.InfraError.OutOfMemory;
    }

    return .{
        .factors = list.toOwnedSlice(env.allocator) catch return errors.InfraError.OutOfMemory,
        .visibility = vis,
    };
}

pub fn pendingFactors(allocator: std.mem.Allocator, state: *const session.SessionState) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    for (state.leaf_slots) |slot| {
        if (slot.phase == .challenged) {
            try list.append(allocator, slot.factor_id);
        }
    }
    return list.toOwnedSlice(allocator);
}
