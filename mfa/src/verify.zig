const std = @import("std");
const primitives = @import("primitives.zig");
const types = @import("types.zig");
const ports = @import("ports.zig");
const errors = @import("errors.zig");
const registry_mod = @import("registry.zig");
const policy = @import("policy.zig");
const fingerprint = @import("fingerprint.zig");
const session = @import("session.zig");
const engine = @import("engine.zig");

pub const SubmitOutcome = union(enum) {
    verified: struct { session_satisfied: bool },
    rejected: void,
    pending: void,
    challenge_continue: []u8,
    rate_limited: u64,

    pub fn deinit(self: *SubmitOutcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .challenge_continue => |c| allocator.free(c),
            else => {},
        }
    }
};

pub const FactorProof = struct {
    factor_id: []const u8,
    proof_bytes: []const u8,
};

pub const SetOutcome = union(enum) {
    verified: struct { session_satisfied: bool },
    rejected: void,
    rate_limited: u64,
};

pub const TakeOutcomeResult = union(enum) {
    terminal: session.ChainOutcome,
    intermediate: session.IntermediateOutcome,
};

fn findSlot(state: *session.SessionState, factor_id: []const u8) ?*session.LeafSlot {
    for (state.leaf_slots) |*slot| {
        if (std.mem.eql(u8, slot.factor_id, factor_id)) return slot;
    }
    return null;
}

fn isSlotSatisfied(state: *const session.SessionState, factor_id: []const u8) bool {
    for (state.leaf_slots) |slot| {
        if (std.mem.eql(u8, slot.factor_id, factor_id)) {
            return slot.phase == .satisfied;
        }
    }
    return false;
}

fn subtreeCats(node: policy.PolicyNode, reg: *const registry_mod.FactorRegistry, state: *const session.SessionState) types.CategorySet {
    return switch (node) {
        .leaf => |l| if (isSlotSatisfied(state, l.factor_id))
            (if (reg.get(l.factor_id)) |d| d.categories else types.CategorySet{})
        else
            types.CategorySet{},
        .all_of, .batch_all_of, .ordered => |children| blk: {
            var cats = types.CategorySet{};
            for (children) |c| cats = cats.merge(subtreeCats(c, reg, state));
            break :blk cats;
        },
        .any_of => |children| blk: {
            for (children) |c| {
                if (evaluateChain(c, reg, state)) break :blk subtreeCats(c, reg, state);
            }
            break :blk types.CategorySet{};
        },
        .threshold => |th| blk: {
            var cats = types.CategorySet{};
            for (th.nodes) |c| {
                if (evaluateChain(c, reg, state)) cats = cats.merge(subtreeCats(c, reg, state));
            }
            break :blk cats;
        },
    };
}

fn evaluateChain(node: policy.PolicyNode, reg: *const registry_mod.FactorRegistry, state: *const session.SessionState) bool {
    switch (node) {
        .leaf => |l| return isSlotSatisfied(state, l.factor_id),
        .all_of, .batch_all_of, .ordered => |children| {
            for (children) |c| {
                if (!evaluateChain(c, reg, state)) return false;
            }
            return true;
        },
        .any_of => |children| {
            for (children) |c| {
                if (evaluateChain(c, reg, state)) return true;
            }
            return false;
        },
        .threshold => |th| {
            var count: u32 = 0;
            var cats = types.CategorySet{};
            for (th.nodes) |c| {
                if (evaluateChain(c, reg, state)) {
                    if (th.distinct_categories) {
                        const c_cats = subtreeCats(c, reg, state);
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
            return count >= th.k;
        },
    }
}

fn markMinimalContributing(node: policy.PolicyNode, reg: *const registry_mod.FactorRegistry, state: *session.SessionState) void {
    for (state.leaf_slots) |*s| s.output.contributing = false;
    markSubtreeContributing(node, reg, state);
}

fn markSubtreeContributing(node: policy.PolicyNode, reg: *const registry_mod.FactorRegistry, state: *session.SessionState) void {
    switch (node) {
        .leaf => |l| {
            if (findSlot(state, l.factor_id)) |slot| {
                if (slot.phase == .satisfied) slot.output.contributing = true;
            }
        },
        .all_of, .batch_all_of, .ordered => |children| {
            for (children) |c| markSubtreeContributing(c, reg, state);
        },
        .any_of => |children| {
            for (children) |c| {
                if (evaluateChain(c, reg, state)) {
                    markSubtreeContributing(c, reg, state);
                    break;
                }
            }
        },
        .threshold => |th| {
            var count: u32 = 0;
            var cats = types.CategorySet{};
            for (th.nodes) |c| {
                if (count >= th.k) break;
                if (evaluateChain(c, reg, state)) {
                    if (th.distinct_categories) {
                        const c_cats = subtreeCats(c, reg, state);
                        const prev_bits = @as(u8, @bitCast(cats)) & 0x07;
                        const cur_bits = @as(u8, @bitCast(c_cats)) & 0x07;
                        if ((prev_bits & cur_bits) == 0 and cur_bits != 0) {
                            markSubtreeContributing(c, reg, state);
                            cats = cats.merge(c_cats);
                            count += 1;
                        }
                    } else {
                        markSubtreeContributing(c, reg, state);
                        count += 1;
                    }
                }
            }
        },
    }
}

fn isInBatch(node: policy.PolicyNode, factor_id: []const u8, in_batch: bool) bool {
    return switch (node) {
        .leaf => |l| in_batch and std.mem.eql(u8, l.factor_id, factor_id),
        .batch_all_of => |children| blk: {
            for (children) |c| {
                if (isInBatch(c, factor_id, true)) break :blk true;
            }
            break :blk false;
        },
        .all_of, .any_of, .ordered => |children| blk: {
            for (children) |c| {
                if (isInBatch(c, factor_id, in_batch)) break :blk true;
            }
            break :blk false;
        },
        .threshold => |th| blk: {
            for (th.nodes) |c| {
                if (isInBatch(c, factor_id, in_batch)) break :blk true;
            }
            break :blk false;
        },
    };
}

fn freeVerifyBuffers(allocator: std.mem.Allocator, sec: std.mem.Allocator, vres: ports.FactorVerifier.VerifyResult) void {
    if (vres.state_update) |su| {
        primitives.wipe(su);
        sec.free(su);
    }
    if (vres.derived_ctx) |dc| {
        primitives.wipe(dc);
        sec.free(dc);
    }
    if (vres.claims) |cl| allocator.free(cl);
    switch (vres.status) {
        .challenge_continue => |cc| {
            allocator.free(cc.payload);
            if (cc.challenge_state) |cs| {
                primitives.wipe(cs);
                sec.free(cs);
            }
        },
        else => {},
    }
}

fn checkVerifyResultLimits(vres: ports.FactorVerifier.VerifyResult, limits: types.SessionLimits) bool {
    if (vres.state_update) |su| if (su.len > limits.max_state_update_len) return false;
    if (vres.derived_ctx) |dc| if (dc.len > limits.max_derived_ctx_len) return false;
    if (vres.claims) |cl| if (cl.len > limits.max_claims_len) return false;
    switch (vres.status) {
        .challenge_continue => |cc| {
            if (cc.payload.len > limits.max_proof_len) return false;
            if (cc.challenge_state) |cs| if (cs.len > limits.max_challenge_state_len) return false;
        },
        else => {},
    }
    return true;
}

pub fn submitProof(
    env: engine.EngineEnv,
    state: *session.SessionState,
    chain: policy.SecurityChain,
    meta: engine.CallMeta,
    factor_id: []const u8,
    proof_bytes: []const u8,
) (errors.MfaError || errors.InfraError)!SubmitOutcome {
    try engine.validateEnv(env);
    if (proof_bytes.len > state.limits.max_proof_len) return errors.MfaError.LimitExceeded;
    if (meta.request_ctx) |rc| {
        if (rc.len > state.limits.max_request_ctx_len) return errors.MfaError.LimitExceeded;
    }
    try engine.verifyBinding(env, state, meta);
    const effective_now = try engine.advanceClock(state, meta.now_unix_s);
    const active = try engine.resolveActivePolicy(env, state, chain, effective_now);
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
    if (isInBatch(active.chain.root, factor_id, false)) return errors.MfaError.BatchRequired;
    switch (engine.checkLeafEligibility(&active.chain.root, state.leaf_slots, factor_id, active.registry)) {
        .eligible => {},
        .not_ready => return errors.MfaError.FactorNotReady,
        .not_needed => return errors.MfaError.FactorNotNeeded,
        .not_found => return errors.MfaError.FactorNotInPolicy,
    }

    const entry = active.registry.getEntry(factor_id) orelse return errors.MfaError.FactorNotFound;
    if (entry.descriptor.requires_challenge and slot.phase != .challenged) {
        return errors.MfaError.ChallengeRequired;
    }

    var challenge_id: ?[32]u8 = null;
    var challenge_state: ?[]const u8 = null;
    if (slot.phase == .challenged) {
        if (effective_now >= slot.phase.challenged.expires_at) {
            return errors.MfaError.ChallengeExpired;
        }
        challenge_id = slot.phase.challenged.factor_challenge_nonce;
        challenge_state = slot.phase.challenged.challenge_state;
    }

    const res_dec = env.tracker.reserve(.verify, .{
        .subject_id = state.subject_id,
        .factor_id = factor_id,
        .session_id = state.session_id,
        .source_key = meta.source_key,
    }, effective_now) catch return errors.InfraError.TrackerError;

    const reservation = switch (res_dec) {
        .granted => |r| r,
        .locked_out => |d| return .{ .rate_limited = d.retry_after_s },
    };

    const transcript = engine.deriveTranscript(
        env.hash,
        state.policy_fingerprint,
        state.session_id,
        state.action_scope,
        state.subject_id,
        factor_id,
        challenge_id orelse @splat(0),
        state.binding_hash,
    );

    const derived_ctxs = try engine.collectDerivedContexts(env.allocator, state, active.chain, factor_id);
    defer if (derived_ctxs.len > 0) env.allocator.free(derived_ctxs);

    const sec = env.secret_allocator orelse env.allocator;
    const max_tries: usize = 1 + @as(usize, state.limits.max_conflict_retries);

    for (0..max_tries) |attempt| {
        const snap = env.store.load(sec, state.subject_id, factor_id) catch {
            env.tracker.settle(reservation, .infra_error, effective_now) catch {};
            return errors.InfraError.StateStoreError;
        };
        defer if (snap.bytes) |b| {
            if (b.len > 0) {
                primitives.wipe(b);
                sec.free(b);
            }
        };

        const vres = entry.verifier.verify(.{
            .allocator = env.allocator,
            .secret_allocator = sec,
            .random = env.random,
            .session_id = state.session_id,
            .subject_id = state.subject_id,
            .action_scope = state.action_scope,
            .factor_id = factor_id,
            .factor_challenge_nonce = challenge_id,
            .transcript = transcript,
            .challenge_state = challenge_state,
            .factor_state = snap.bytes,
            .factor_state_version = snap.version,
            .enrollment_mode = state.enrollment_mode,
            .now_unix_s = effective_now,
            .request_ctx = meta.request_ctx,
            .derived_contexts = derived_ctxs,
        }, proof_bytes) catch |e| {
            env.tracker.settle(reservation, .infra_error, effective_now) catch {};
            return switch (e) {
                error.OutOfMemory => errors.InfraError.OutOfMemory,
                error.VerifierIoError => errors.InfraError.VerifierIoError,
            };
        };

        if (!checkVerifyResultLimits(vres, state.limits)) {
            freeVerifyBuffers(env.allocator, sec, vres);
            env.tracker.settle(reservation, .rejected, effective_now) catch return errors.InfraError.TrackerError;
            state.failed_verifications += 1;
            state.last_activity_at = effective_now;
            state.version += 1;
            if (state.failed_verifications >= state.limits.max_failed_verifications_per_session) {
                engine.wipeAllChallenges(sec, state);
                state.status = .invalidated;
            }
            return errors.InfraError.VerifierProtocolViolation;
        }

        const is_decoy = slot.phase == .challenged and slot.phase.challenged.decoy;
        if (is_decoy or vres.status == .rejected) {
            env.tracker.settle(reservation, .rejected, effective_now) catch |err| {
                freeVerifyBuffers(env.allocator, sec, vres);
                return switch (err) {
                    error.OutOfMemory => errors.InfraError.OutOfMemory,
                    else => errors.InfraError.TrackerError,
                };
            };
            if (vres.state_update) |new_state| {
                _ = env.store.commit(state.subject_id, factor_id, snap.version, new_state) catch {
                    freeVerifyBuffers(env.allocator, sec, vres);
                    return errors.InfraError.StateStoreError;
                };
            }
            freeVerifyBuffers(env.allocator, sec, vres);

            state.failed_verifications += 1;
            state.last_activity_at = effective_now;
            state.version += 1;
            if (state.failed_verifications >= state.limits.max_failed_verifications_per_session) {
                engine.wipeAllChallenges(sec, state);
                state.status = .invalidated;
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
            }
            if (env.audit) |a| {
                a.emit(.{
                    .kind = .proof_rejected,
                    .now_unix_s = effective_now,
                    .subject_id = state.subject_id,
                    .session_id = state.session_id,
                    .factor_id = factor_id,
                    .source_key = meta.source_key,
                });
            }
            return .rejected;
        }

        switch (vres.status) {
            .pending => {
                if (vres.state_update) |su| {
                    primitives.wipe(su);
                    sec.free(su);
                }
                if (vres.derived_ctx) |dc| {
                    primitives.wipe(dc);
                    sec.free(dc);
                }
                if (vres.claims) |cl| env.allocator.free(cl);
                env.tracker.settle(reservation, .pending, effective_now) catch return errors.InfraError.TrackerError;
                state.last_activity_at = effective_now;
                state.version += 1;
                return .pending;
            },
            .challenge_continue => |cc| {
                if (vres.state_update) |su| {
                    primitives.wipe(su);
                    sec.free(su);
                }
                if (vres.derived_ctx) |dc| {
                    primitives.wipe(dc);
                    sec.free(dc);
                }
                if (vres.claims) |cl| env.allocator.free(cl);

                if (slot.phase != .challenged or slot.phase.challenged.rounds >= state.limits.max_challenge_rounds_per_leaf) {
                    env.allocator.free(cc.payload);
                    if (cc.challenge_state) |cs| {
                        primitives.wipe(cs);
                        sec.free(cs);
                    }
                    env.tracker.settle(reservation, .rejected, effective_now) catch return errors.InfraError.TrackerError;
                    return errors.MfaError.LimitExceeded;
                }

                env.tracker.settle(reservation, .challenge_issued, effective_now) catch |err| {
                    env.allocator.free(cc.payload);
                    if (cc.challenge_state) |cs| {
                        primitives.wipe(cs);
                        sec.free(cs);
                    }
                    return switch (err) {
                        error.OutOfMemory => errors.InfraError.OutOfMemory,
                        else => errors.InfraError.TrackerError,
                    };
                };

                if (slot.phase.challenged.challenge_state) |old_cs| {
                    primitives.wipe(old_cs);
                    sec.free(old_cs);
                }
                const chal_exp: i64 = if (cc.ttl_s) |t| blk: {
                    const t_i64 = std.math.cast(i64, t) orelse break :blk state.expires_at;
                    const sum = std.math.add(i64, effective_now, t_i64) catch break :blk state.expires_at;
                    break :blk @min(state.expires_at, sum);
                } else state.expires_at;

                slot.phase.challenged.issued_at = effective_now;
                slot.phase.challenged.expires_at = chal_exp;
                slot.phase.challenged.challenge_state = cc.challenge_state;
                slot.phase.challenged.rounds += 1;
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
                return .{ .challenge_continue = cc.payload };
            },
            .verified => {
                if (vres.state_update) |new_state| {
                    const cres = env.store.commit(state.subject_id, factor_id, snap.version, new_state) catch {
                        freeVerifyBuffers(env.allocator, sec, vres);
                        env.tracker.settle(reservation, .infra_error, effective_now) catch {};
                        return errors.InfraError.StateStoreError;
                    };
                    primitives.wipe(new_state);
                    sec.free(new_state);

                    if (cres == .conflict) {
                        if (vres.derived_ctx) |dc| {
                            primitives.wipe(dc);
                            sec.free(dc);
                        }
                        if (vres.claims) |cl| env.allocator.free(cl);
                        if (attempt + 1 < max_tries) {
                            if (env.audit) |a| {
                                a.emit(.{
                                    .kind = .conflict_retry,
                                    .now_unix_s = effective_now,
                                    .subject_id = state.subject_id,
                                    .session_id = state.session_id,
                                    .factor_id = factor_id,
                                    .source_key = meta.source_key,
                                });
                            }
                            continue;
                        }
                        if (env.audit) |a| {
                            a.emit(.{
                                .kind = .conflict_exhausted,
                                .now_unix_s = effective_now,
                                .subject_id = state.subject_id,
                                .session_id = state.session_id,
                                .factor_id = factor_id,
                                .source_key = meta.source_key,
                            });
                        }
                        env.tracker.settle(reservation, .infra_error, effective_now) catch {};
                        return errors.InfraError.StateStoreError;
                    }
                }

                env.tracker.settle(reservation, .verified, effective_now) catch |err| {
                    if (vres.derived_ctx) |dc| {
                        primitives.wipe(dc);
                        sec.free(dc);
                    }
                    if (vres.claims) |cl| env.allocator.free(cl);
                    return switch (err) {
                        error.OutOfMemory => errors.InfraError.OutOfMemory,
                        else => errors.InfraError.TrackerError,
                    };
                };

                if (slot.phase == .challenged) {
                    if (slot.phase.challenged.challenge_state) |cs| {
                        primitives.wipe(cs);
                        sec.free(cs);
                    }
                }
                slot.phase = .satisfied;
                slot.output.verified_at = effective_now;
                slot.output.derived_ctx = vres.derived_ctx;
                slot.output.claims = vres.claims;
                if (entry.descriptor.is_recovery) {
                    state.used_recovery = true;
                    if (env.audit) |a| {
                        a.emit(.{
                            .kind = .recovery_used,
                            .now_unix_s = effective_now,
                            .subject_id = state.subject_id,
                            .session_id = state.session_id,
                            .factor_id = factor_id,
                            .source_key = meta.source_key,
                        });
                    }
                }
                state.last_activity_at = effective_now;
                state.version += 1;

                const satisfied = evaluateChain(active.chain.root, active.registry, state);
                if (satisfied) {
                    markMinimalContributing(active.chain.root, active.registry, state);
                    state.status = .satisfied;
                    state.completed_at = effective_now;
                }

                if (env.audit) |a| {
                    a.emit(.{
                        .kind = .proof_verified,
                        .now_unix_s = effective_now,
                        .subject_id = state.subject_id,
                        .session_id = state.session_id,
                        .factor_id = factor_id,
                        .source_key = meta.source_key,
                    });
                }
                return .{ .verified = .{ .session_satisfied = satisfied } };
            },
            .rejected => unreachable,
        }
    }

    env.tracker.settle(reservation, .infra_error, effective_now) catch {};
    return errors.InfraError.StateStoreError;
}

fn containsProofFactor(proofs: []const FactorProof, factor_id: []const u8) bool {
    for (proofs) |p| {
        if (std.mem.eql(u8, p.factor_id, factor_id)) return true;
    }
    return false;
}

fn checkBatchSubtree(node: policy.PolicyNode, state: *const session.SessionState, proofs: []const FactorProof) errors.MfaError!void {
    switch (node) {
        .batch_all_of => |children| {
            var any_in_proofs = false;
            var all_unsat_covered = true;
            const helper = struct {
                fn scan(n: policy.PolicyNode, st: *const session.SessionState, pr: []const FactorProof, any_in: *bool, all_cov: *bool) void {
                    switch (n) {
                        .leaf => |l| {
                            const in_p = containsProofFactor(pr, l.factor_id);
                            if (in_p) any_in.* = true;
                            if (!isSlotSatisfied(st, l.factor_id) and !in_p) {
                                all_cov.* = false;
                            }
                        },
                        .batch_all_of, .all_of, .any_of, .ordered => |ch| {
                            for (ch) |c| scan(c, st, pr, any_in, all_cov);
                        },
                        .threshold => |th| {
                            for (th.nodes) |c| scan(c, st, pr, any_in, all_cov);
                        },
                    }
                }
            };
            for (children) |c| {
                helper.scan(c, state, proofs, &any_in_proofs, &all_unsat_covered);
            }
            if (any_in_proofs and !all_unsat_covered) {
                return errors.MfaError.BatchRequired;
            }
        },
        .all_of, .any_of, .ordered => |children| {
            for (children) |c| try checkBatchSubtree(c, state, proofs);
        },
        .threshold => |th| {
            for (th.nodes) |c| try checkBatchSubtree(c, state, proofs);
        },
        .leaf => {},
    }
}

pub fn submitProofSet(
    env: engine.EngineEnv,
    state: *session.SessionState,
    chain: policy.SecurityChain,
    meta: engine.CallMeta,
    proofs: []const FactorProof,
) (errors.MfaError || errors.InfraError)!SetOutcome {
    try engine.validateEnv(env);
    if (proofs.len == 0 or proofs.len > types.max_policy_leaves) {
        return errors.MfaError.LimitExceeded;
    }
    if (meta.request_ctx) |rc| {
        if (rc.len > state.limits.max_request_ctx_len) return errors.MfaError.LimitExceeded;
    }
    for (proofs) |p| {
        if (p.proof_bytes.len > state.limits.max_proof_len) return errors.MfaError.LimitExceeded;
    }

    try engine.verifyBinding(env, state, meta);
    const effective_now = try engine.advanceClock(state, meta.now_unix_s);
    const active = try engine.resolveActivePolicy(env, state, chain, effective_now);
    try session.checkInvariants(state, active.chain, active.registry);

    if (state.status == .invalidated) return errors.MfaError.SessionInvalidated;
    if (state.status == .expired) return errors.MfaError.SessionExpired;
    if (state.status != .active) return errors.MfaError.SessionCompleted;
    if (effective_now >= state.expires_at) {
        state.status = .expired;
        return errors.MfaError.SessionExpired;
    }

    for (proofs, 0..) |p, i| {
        for (proofs[i + 1 ..]) |q| {
            if (std.mem.eql(u8, p.factor_id, q.factor_id)) return errors.MfaError.InvalidPolicy;
        }
        const slot = findSlot(state, p.factor_id) orelse return errors.MfaError.FactorNotInPolicy;
        if (slot.phase == .satisfied) return errors.MfaError.FactorAlreadySatisfied;
        switch (engine.checkLeafEligibility(&active.chain.root, state.leaf_slots, p.factor_id, active.registry)) {
            .eligible => {},
            .not_ready => return errors.MfaError.FactorNotReady,
            .not_needed => return errors.MfaError.FactorNotNeeded,
            .not_found => return errors.MfaError.FactorNotInPolicy,
        }
        const entry = active.registry.getEntry(p.factor_id) orelse return errors.MfaError.FactorNotFound;
        if (entry.descriptor.requires_challenge and slot.phase != .challenged) {
            return errors.MfaError.ChallengeRequired;
        }
        if (slot.phase == .challenged and effective_now >= slot.phase.challenged.expires_at) {
            return errors.MfaError.ChallengeExpired;
        }
    }

    try checkBatchSubtree(active.chain.root, state, proofs);

    // Build sorted batch_key joined by 0x1F
    var sorted_ids: [types.max_policy_leaves][]const u8 = undefined;
    for (proofs, 0..) |p, i| sorted_ids[i] = p.factor_id;
    std.sort.pdq([]const u8, sorted_ids[0..proofs.len], {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    var batch_key_buf: std.ArrayList(u8) = .empty;
    defer batch_key_buf.deinit(env.allocator);
    for (sorted_ids[0..proofs.len], 0..) |fid, i| {
        if (i > 0) batch_key_buf.append(env.allocator, 0x1F) catch return errors.InfraError.OutOfMemory;
        batch_key_buf.appendSlice(env.allocator, fid) catch return errors.InfraError.OutOfMemory;
    }

    const res_dec = env.tracker.reserve(.verify, .{
        .subject_id = state.subject_id,
        .factor_id = null,
        .session_id = state.session_id,
        .source_key = meta.source_key,
        .batch_key = batch_key_buf.items,
    }, effective_now) catch return errors.InfraError.TrackerError;

    const reservation = switch (res_dec) {
        .granted => |r| r,
        .locked_out => |d| return .{ .rate_limited = d.retry_after_s },
    };

    const sec = env.secret_allocator orelse env.allocator;
    const EvalEntry = struct {
        vres: ports.FactorVerifier.VerifyResult,
        snap_version: u64,
        is_recovery: bool,
    };
    var results: [types.max_policy_leaves]EvalEntry = undefined;
    var eval_count: usize = 0;
    errdefer {
        for (results[0..eval_count]) |r| freeVerifyBuffers(env.allocator, sec, r.vres);
    }

    var all_ok = true;
    var protocol_violation = false;

    for (proofs, 0..) |p, i| {
        const slot = findSlot(state, p.factor_id).?;
        const entry = active.registry.getEntry(p.factor_id).?;
        const challenge_id: ?[32]u8 = if (slot.phase == .challenged) slot.phase.challenged.factor_challenge_nonce else null;
        const challenge_state: ?[]const u8 = if (slot.phase == .challenged) slot.phase.challenged.challenge_state else null;
        const is_decoy = slot.phase == .challenged and slot.phase.challenged.decoy;

        const transcript = engine.deriveTranscript(
            env.hash,
            state.policy_fingerprint,
            state.session_id,
            state.action_scope,
            state.subject_id,
            p.factor_id,
            challenge_id orelse @splat(0),
            state.binding_hash,
        );

        const derived_ctxs = engine.collectDerivedContexts(env.allocator, state, active.chain, p.factor_id) catch |e| {
            env.tracker.settle(reservation, .infra_error, effective_now) catch {};
            return e;
        };
        defer if (derived_ctxs.len > 0) env.allocator.free(derived_ctxs);

        const snap = env.store.load(sec, state.subject_id, p.factor_id) catch {
            env.tracker.settle(reservation, .infra_error, effective_now) catch {};
            return errors.InfraError.StateStoreError;
        };
        defer if (snap.bytes) |b| {
            if (b.len > 0) {
                primitives.wipe(b);
                sec.free(b);
            }
        };

        const vres = entry.verifier.verify(.{
            .allocator = env.allocator,
            .secret_allocator = sec,
            .random = env.random,
            .session_id = state.session_id,
            .subject_id = state.subject_id,
            .action_scope = state.action_scope,
            .factor_id = p.factor_id,
            .factor_challenge_nonce = challenge_id,
            .transcript = transcript,
            .challenge_state = challenge_state,
            .factor_state = snap.bytes,
            .factor_state_version = snap.version,
            .enrollment_mode = state.enrollment_mode,
            .now_unix_s = effective_now,
            .request_ctx = meta.request_ctx,
            .derived_contexts = derived_ctxs,
        }, p.proof_bytes) catch |e| {
            env.tracker.settle(reservation, .infra_error, effective_now) catch {};
            return switch (e) {
                error.OutOfMemory => errors.InfraError.OutOfMemory,
                error.VerifierIoError => errors.InfraError.VerifierIoError,
            };
        };

        results[i] = .{
            .vres = vres,
            .snap_version = snap.version,
            .is_recovery = entry.descriptor.is_recovery,
        };
        eval_count += 1;

        if (!checkVerifyResultLimits(vres, state.limits)) {
            protocol_violation = true;
            all_ok = false;
        } else if (is_decoy or vres.status != .verified) {
            all_ok = false;
        }
    }

    if (!all_ok) {
        defer {
            for (results[0..eval_count]) |r| freeVerifyBuffers(env.allocator, sec, r.vres);
            eval_count = 0;
        }
        env.tracker.settle(reservation, .rejected, effective_now) catch return errors.InfraError.TrackerError;
        for (results[0..eval_count], 0..) |r, i| {
            if (r.vres.state_update) |su| {
                _ = env.store.commit(state.subject_id, proofs[i].factor_id, r.snap_version, su) catch {
                    return errors.InfraError.StateStoreError;
                };
            }
        }
        state.failed_verifications += 1;
        state.last_activity_at = effective_now;
        state.version += 1;
        if (state.failed_verifications >= state.limits.max_failed_verifications_per_session) {
            engine.wipeAllChallenges(sec, state);
            state.status = .invalidated;
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
        if (env.audit) |a| {
            a.emit(.{
                .kind = .proof_rejected,
                .now_unix_s = effective_now,
                .subject_id = state.subject_id,
                .session_id = state.session_id,
                .source_key = meta.source_key,
            });
        }
        if (protocol_violation) return errors.InfraError.VerifierProtocolViolation;
        return .rejected;
    }

    // Commit state_updates with CAS retries if needed
    for (proofs, 0..) |p, i| {
        if (results[i].vres.state_update) |su| {
            const cres = env.store.commit(state.subject_id, p.factor_id, results[i].snap_version, su) catch {
                env.tracker.settle(reservation, .infra_error, effective_now) catch {};
                return errors.InfraError.StateStoreError;
            };
            if (cres == .conflict) {
                env.tracker.settle(reservation, .infra_error, effective_now) catch {};
                return errors.InfraError.StateStoreError;
            }
            primitives.wipe(su);
            sec.free(su);
            results[i].vres.state_update = null;
        }
    }

    env.tracker.settle(reservation, .verified, effective_now) catch return errors.InfraError.TrackerError;
    for (proofs, 0..) |p, i| {
        const slot = findSlot(state, p.factor_id).?;
        if (slot.phase == .challenged) {
            if (slot.phase.challenged.challenge_state) |cs| {
                primitives.wipe(cs);
                sec.free(cs);
            }
        }
        slot.phase = .satisfied;
        slot.output.verified_at = effective_now;
        slot.output.derived_ctx = results[i].vres.derived_ctx;
        slot.output.claims = results[i].vres.claims;
        results[i].vres.derived_ctx = null;
        results[i].vres.claims = null;
        if (results[i].is_recovery) {
            state.used_recovery = true;
            if (env.audit) |a| {
                a.emit(.{
                    .kind = .recovery_used,
                    .now_unix_s = effective_now,
                    .subject_id = state.subject_id,
                    .session_id = state.session_id,
                    .factor_id = p.factor_id,
                    .source_key = meta.source_key,
                });
            }
        }
        if (env.audit) |a| {
            a.emit(.{
                .kind = .proof_verified,
                .now_unix_s = effective_now,
                .subject_id = state.subject_id,
                .session_id = state.session_id,
                .factor_id = p.factor_id,
                .source_key = meta.source_key,
            });
        }
    }
    eval_count = 0;

    state.last_activity_at = effective_now;
    state.version += 1;
    const satisfied = evaluateChain(active.chain.root, active.registry, state);
    if (satisfied) {
        markMinimalContributing(active.chain.root, active.registry, state);
        state.status = .satisfied;
        state.completed_at = effective_now;
    }
    return .{ .verified = .{ .session_satisfied = satisfied } };
}

pub fn takeOutcome(
    env: engine.EngineEnv,
    state: *session.SessionState,
    chain: policy.SecurityChain,
    meta: engine.CallMeta,
) (errors.MfaError || errors.InfraError)!TakeOutcomeResult {
    try engine.validateEnv(env);
    try engine.verifyBinding(env, state, meta);
    const effective_now = try engine.advanceClock(state, meta.now_unix_s);
    const active = try engine.resolveActivePolicy(env, state, chain, effective_now);
    try session.checkInvariants(state, active.chain, active.registry);

    if (state.status == .consumed) return errors.MfaError.OutcomeAlreadyTaken;
    if (state.status == .invalidated) return errors.MfaError.SessionInvalidated;
    if (state.status == .expired) return errors.MfaError.SessionExpired;
    if (state.status != .satisfied) return errors.MfaError.SessionNotSatisfied;
    if (effective_now >= state.expires_at) {
        state.status = .expired;
        return errors.MfaError.SessionExpired;
    }
    if (!evaluateChain(active.chain.root, active.registry, state)) {
        return errors.MfaError.SessionNotSatisfied;
    }

    markMinimalContributing(active.chain.root, active.registry, state);

    var cats = types.CategorySet{};
    var contrib_count: usize = 0;
    for (state.leaf_slots) |slot| {
        if (slot.phase == .satisfied and slot.output.contributing) {
            contrib_count += 1;
            if (active.registry.get(slot.factor_id)) |d| {
                cats = cats.merge(d.categories);
            }
        }
    }

    const factors = env.allocator.alloc(session.FactorOutput, contrib_count) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(factors);
    const sid_copy = env.allocator.dupe(u8, state.session_id) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(sid_copy);
    const sub_copy = env.allocator.dupe(u8, state.subject_id) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(sub_copy);
    const scope_copy = env.allocator.dupe(u8, state.action_scope) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(scope_copy);

    var idx: usize = 0;
    for (state.leaf_slots) |*slot| {
        if (slot.phase == .satisfied and slot.output.contributing) {
            factors[idx] = slot.output;
            slot.output = .{ .factor_id = "" };
            idx += 1;
        }
    }

    state.status = .consumed;
    state.last_activity_at = effective_now;
    state.version += 1;

    if (state.outcome_class == .intermediate) {
        return .{ .intermediate = .{
            .subject_id = sub_copy,
            .action_scope = scope_copy,
            .session_id = sid_copy,
            .policy_fingerprint = state.policy_fingerprint,
            .binding_mode = state.binding_mode,
            .binding_hash = state.binding_hash,
            .max_grant_ttl_s = state.limits.max_grant_ttl_s,
            .completed_at = state.completed_at orelse effective_now,
            .expires_at = state.expires_at,
            .categories_mask = cats,
            .used_recovery = state.used_recovery,
            .satisfied_factors = factors,
        } };
    }

    return .{ .terminal = .{
        .subject_id = sub_copy,
        .action_scope = scope_copy,
        .session_id = sid_copy,
        .policy_fingerprint = state.policy_fingerprint,
        .binding_mode = state.binding_mode,
        .binding_hash = state.binding_hash,
        .max_grant_ttl_s = state.limits.max_grant_ttl_s,
        .completed_at = state.completed_at orelse effective_now,
        .expires_at = state.expires_at,
        .categories_mask = cats,
        .used_recovery = state.used_recovery,
        .satisfied_factors = factors,
    } };
}

pub fn composeOutcomes(
    env: engine.EngineEnv,
    intermediate: *session.IntermediateOutcome,
    terminal: *session.ChainOutcome,
    now_unix_s: i64,
    max_step_up_gap_s: u64,
    skew_tolerance_s: u64,
) (errors.MfaError || errors.InfraError)!session.ChainOutcome {
    try engine.validateEnv(env);
    if (intermediate.binding_mode != .bound or terminal.binding_mode != .bound) {
        return errors.MfaError.WeakBinding;
    }
    if (!std.mem.eql(u8, intermediate.subject_id, terminal.subject_id)) {
        return errors.MfaError.SessionBindingMismatch;
    }
    const bh_i = intermediate.binding_hash orelse return errors.MfaError.SessionBindingMismatch;
    const bh_t = terminal.binding_hash orelse return errors.MfaError.SessionBindingMismatch;
    if (!primitives.ctEql32(&bh_i, &bh_t)) {
        return errors.MfaError.SessionBindingMismatch;
    }
    if (now_unix_s >= intermediate.expires_at or now_unix_s >= terminal.expires_at) {
        return errors.MfaError.SessionExpired;
    }
    const skew_i64 = std.math.cast(i64, skew_tolerance_s) orelse return errors.MfaError.LimitExceeded;
    if (intermediate.completed_at > terminal.completed_at + skew_i64) {
        return errors.MfaError.ClockSkewDetected;
    }
    const gap: i64 = @max(0, terminal.completed_at - intermediate.completed_at);
    const max_gap_i64 = std.math.cast(i64, max_step_up_gap_s) orelse std.math.maxInt(i64);
    if (gap > max_gap_i64) {
        return errors.MfaError.SessionExpired;
    }

    const composed_fp = fingerprint.composedPolicyFingerprint(env.hash, intermediate.policy_fingerprint, terminal.policy_fingerprint);
    const sid_hex = fingerprint.composedSessionId(env.hash, intermediate.session_id, terminal.session_id);

    const total_factors = intermediate.satisfied_factors.len + terminal.satisfied_factors.len;
    const merged = env.allocator.alloc(session.FactorOutput, total_factors) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(merged);
    const sub_copy = env.allocator.dupe(u8, terminal.subject_id) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(sub_copy);
    const scope_copy = env.allocator.dupe(u8, terminal.action_scope) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(scope_copy);
    const sid_copy = env.allocator.dupe(u8, &sid_hex) catch return errors.InfraError.OutOfMemory;
    errdefer env.allocator.free(sid_copy);

    for (intermediate.satisfied_factors, 0..) |*f, i| {
        merged[i] = f.*;
        f.* = .{ .factor_id = "" };
    }
    for (terminal.satisfied_factors, 0..) |*f, i| {
        merged[intermediate.satisfied_factors.len + i] = f.*;
        f.* = .{ .factor_id = "" };
    }

    const completed_at = @max(intermediate.completed_at, terminal.completed_at);
    const max_grant_ttl_s = @min(intermediate.max_grant_ttl_s, terminal.max_grant_ttl_s);
    const expires_at = @min(intermediate.expires_at, terminal.expires_at);
    const cats = intermediate.categories_mask.merge(terminal.categories_mask);
    const used_recovery = intermediate.used_recovery or terminal.used_recovery;

    intermediate.deinit(env.allocator, env.secret_allocator);
    terminal.deinit(env.allocator, env.secret_allocator);

    if (env.audit) |a| {
        a.emit(.{
            .kind = .outcomes_composed,
            .now_unix_s = now_unix_s,
            .subject_id = sub_copy,
            .session_id = sid_copy,
        });
    }

    return .{
        .subject_id = sub_copy,
        .action_scope = scope_copy,
        .session_id = sid_copy,
        .policy_fingerprint = composed_fp,
        .binding_mode = .bound,
        .binding_hash = bh_t,
        .max_grant_ttl_s = max_grant_ttl_s,
        .completed_at = completed_at,
        .expires_at = expires_at,
        .categories_mask = cats,
        .used_recovery = used_recovery,
        .satisfied_factors = merged,
    };
}

pub fn sealGrant(
    env: engine.EngineEnv,
    signer: ports.GrantSigner,
    outcome: session.ChainOutcome,
    grant_spec: ports.GrantSigner.GrantSpec,
) (errors.MfaError || errors.InfraError)!ports.GrantSigner.SealedGrant {
    try engine.validateEnv(env);
    if (grant_spec.audience.len == 0) return errors.MfaError.InvalidPolicy;
    if (grant_spec.ttl_s == 0 or grant_spec.ttl_s > outcome.max_grant_ttl_s) return errors.MfaError.LimitExceeded;

    const tok = signer.seal(env.allocator, &outcome, grant_spec) catch |e| switch (e) {
        error.OutOfMemory => return errors.InfraError.OutOfMemory,
        else => return errors.InfraError.GrantSignError,
    };
    if (env.audit) |a| {
        a.emit(.{
            .kind = .grant_sealed,
            .now_unix_s = outcome.completed_at,
            .subject_id = outcome.subject_id,
            .session_id = outcome.session_id,
        });
    }
    return .{ .token = tok };
}
