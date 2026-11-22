const std = @import("std");
const types = @import("types.zig");
const ports = @import("ports.zig");
const errors = @import("errors.zig");
const registry_mod = @import("registry.zig");

pub const ContextDependency = struct {
    factor_id: []const u8,
    required: bool = true,
};

pub const LeafNode = struct {
    factor_id: []const u8,
    reads_ctx_from: []const ContextDependency = &.{},
};

pub const ThresholdNode = struct {
    k: u32,
    distinct_categories: bool = false,
    nodes: []const PolicyNode,
};

pub const PolicyNode = union(enum) {
    leaf: LeafNode,
    all_of: []const PolicyNode,
    batch_all_of: []const PolicyNode,
    any_of: []const PolicyNode,
    threshold: ThresholdNode,
    ordered: []const PolicyNode,
};

pub const SecurityChain = struct {
    action_scope: []const u8,
    root: PolicyNode,
};

pub const PolicyEnv = struct {
    registry: *const registry_mod.FactorRegistry,
    store: ports.FactorStateStore,
};

pub fn isReservedScope(scope: []const u8) bool {
    return std.mem.eql(u8, scope, "factor_enroll") or
        std.mem.eql(u8, scope, "factor_remove") or
        std.mem.eql(u8, scope, "account_recovery") or
        std.mem.eql(u8, scope, "policy_change");
}

const LeafInfo = struct {
    factor_id: []const u8,
    reads_ctx_from: []const ContextDependency,
    path: [types.max_policy_depth]usize,
    depth: usize,
};

const ValidateCtx = struct {
    env: PolicyEnv,
    assurance: types.AssurancePolicy,
    enrollment_mode: types.EnrollmentMode,
    limits: types.SessionLimits,
    seen_ptrs: [types.max_policy_leaves * 4]usize = undefined,
    seen_ptr_count: usize = 0,
    leaves: [types.max_policy_leaves]LeafInfo = undefined,
    leaf_count: usize = 0,
};

fn recordPtr(ctx: *ValidateCtx, ptr: usize) errors.MfaError!void {
    for (ctx.seen_ptrs[0..ctx.seen_ptr_count]) |p| {
        if (p == ptr) return errors.MfaError.InvalidPolicy;
    }
    if (ctx.seen_ptr_count >= ctx.seen_ptrs.len) return errors.MfaError.InvalidPolicy;
    ctx.seen_ptrs[ctx.seen_ptr_count] = ptr;
    ctx.seen_ptr_count += 1;
}

fn validateNode(
    ctx: *ValidateCtx,
    node: *const PolicyNode,
    depth: usize,
    in_batch: bool,
    path: *[types.max_policy_depth]usize,
) errors.MfaError!struct { leaf_count: usize, categories: types.CategorySet } {
    if (depth >= types.max_policy_depth) return errors.MfaError.InvalidPolicy;
    try recordPtr(ctx, @intFromPtr(node));

    switch (node.*) {
        .leaf => |leaf| {
            if (ctx.leaf_count >= types.max_policy_leaves) return errors.MfaError.InvalidPolicy;
            const desc = ctx.env.registry.get(leaf.factor_id) orelse return errors.MfaError.FactorNotFound;

            for (ctx.leaves[0..ctx.leaf_count]) |existing| {
                if (std.mem.eql(u8, existing.factor_id, leaf.factor_id)) {
                    return errors.MfaError.DuplicateFactorId;
                }
            }

            if (ctx.enrollment_mode == .lazy_on_challenge and !desc.supports_lazy_mode) {
                return errors.MfaError.InvalidPolicy;
            }
            if (desc.statefulness == .stateful and !ctx.env.store.isPersistent()) {
                return errors.MfaError.InvalidPolicy;
            }
            if (desc.requires_challenge and ctx.limits.max_active_challenges < 1) {
                return errors.MfaError.InvalidPolicy;
            }
            if (in_batch) {
                if (!desc.supports_batch) return errors.MfaError.InvalidPolicy;
                if (desc.statefulness == .stateful and !ctx.assurance.allow_stateful_in_batch) {
                    return errors.MfaError.InvalidPolicy;
                }
            }

            var info = LeafInfo{
                .factor_id = leaf.factor_id,
                .reads_ctx_from = leaf.reads_ctx_from,
                .path = undefined,
                .depth = depth,
            };
            @memcpy(info.path[0..depth], path[0..depth]);
            ctx.leaves[ctx.leaf_count] = info;
            ctx.leaf_count += 1;

            return .{ .leaf_count = 1, .categories = desc.categories };
        },
        .all_of => |children| {
            if (in_batch) return errors.MfaError.InvalidPolicy;
            if (children.len == 0) return errors.MfaError.InvalidPolicy;
            var total_leaves: usize = 0;
            var cats = types.CategorySet{};
            for (children, 0..) |*child, i| {
                path[depth] = i;
                const res = try validateNode(ctx, child, depth + 1, false, path);
                total_leaves += res.leaf_count;
                cats = cats.merge(res.categories);
            }
            if (total_leaves >= 2 and !ctx.assurance.allow_unordered_all_of) {
                return errors.MfaError.InvalidPolicy;
            }
            return .{ .leaf_count = total_leaves, .categories = cats };
        },
        .batch_all_of => |children| {
            if (children.len == 0) return errors.MfaError.InvalidPolicy;
            var total_leaves: usize = 0;
            var cats = types.CategorySet{};
            for (children, 0..) |*child, i| {
                switch (child.*) {
                    .leaf, .batch_all_of => {},
                    else => return errors.MfaError.InvalidPolicy,
                }
                path[depth] = i;
                const res = try validateNode(ctx, child, depth + 1, true, path);
                total_leaves += res.leaf_count;
                cats = cats.merge(res.categories);
            }
            return .{ .leaf_count = total_leaves, .categories = cats };
        },
        .any_of => |children| {
            if (in_batch) return errors.MfaError.InvalidPolicy;
            if (children.len == 0) return errors.MfaError.InvalidPolicy;
            var total_leaves: usize = 0;
            var cats = types.CategorySet{};
            for (children, 0..) |*child, i| {
                path[depth] = i;
                const res = try validateNode(ctx, child, depth + 1, false, path);
                total_leaves += res.leaf_count;
                cats = cats.merge(res.categories);
            }
            return .{ .leaf_count = total_leaves, .categories = cats };
        },
        .ordered => |children| {
            if (in_batch) return errors.MfaError.InvalidPolicy;
            if (children.len == 0) return errors.MfaError.InvalidPolicy;
            var total_leaves: usize = 0;
            var cats = types.CategorySet{};
            for (children, 0..) |*child, i| {
                path[depth] = i;
                const res = try validateNode(ctx, child, depth + 1, false, path);
                total_leaves += res.leaf_count;
                cats = cats.merge(res.categories);
            }
            return .{ .leaf_count = total_leaves, .categories = cats };
        },
        .threshold => |th| {
            if (in_batch) return errors.MfaError.InvalidPolicy;
            if (th.nodes.len == 0 or th.k == 0 or th.k > th.nodes.len) {
                return errors.MfaError.InvalidPolicy;
            }
            var total_leaves: usize = 0;
            var cats = types.CategorySet{};
            for (th.nodes, 0..) |*child, i| {
                path[depth] = i;
                const res = try validateNode(ctx, child, depth + 1, false, path);
                if (th.distinct_categories) {
                    if (subtreeUniformCategories(child, ctx.env.registry) == null) {
                        return errors.MfaError.InvalidPolicy;
                    }
                }
                total_leaves += res.leaf_count;
                cats = cats.merge(res.categories);
            }
            if (th.distinct_categories and cats.count() < th.k) {
                return errors.MfaError.PolicyUnsatisfiable;
            }
            return .{ .leaf_count = total_leaves, .categories = cats };
        },
    }
}

fn subtreeUniformCategories(node: *const PolicyNode, reg: *const registry_mod.FactorRegistry) ?types.CategorySet {
    return switch (node.*) {
        .leaf => |l| if (reg.get(l.factor_id)) |desc| desc.categories else null,
        .all_of, .batch_all_of, .any_of, .ordered => |children| blk: {
            if (children.len == 0) break :blk null;
            const first = subtreeUniformCategories(&children[0], reg) orelse break :blk null;
            for (children[1..]) |*c| {
                const cc = subtreeUniformCategories(c, reg) orelse break :blk null;
                if ((@as(u8, @bitCast(first)) & 0x07) != (@as(u8, @bitCast(cc)) & 0x07)) break :blk null;
            }
            break :blk first;
        },
        .threshold => |th| blk: {
            if (th.nodes.len == 0) break :blk null;
            const first = subtreeUniformCategories(&th.nodes[0], reg) orelse break :blk null;
            for (th.nodes[1..]) |*c| {
                const cc = subtreeUniformCategories(c, reg) orelse break :blk null;
                if ((@as(u8, @bitCast(first)) & 0x07) != (@as(u8, @bitCast(cc)) & 0x07)) break :blk null;
            }
            break :blk first;
        },
    };
}

fn findOrderedAncestor(root: *const PolicyNode, a: LeafInfo, b: LeafInfo, require_dominance: bool) bool {
    const min_depth = @min(a.depth, b.depth);
    var cur: *const PolicyNode = root;
    for (0..min_depth) |d| {
        if (a.path[d] != b.path[d]) {
            if (cur.* != .ordered or a.path[d] >= b.path[d]) {
                return false;
            }
            if (!require_dominance) return true;
            var p: *const PolicyNode = &cur.ordered[a.path[d]];
            for (d + 1..a.depth) |k| {
                p = switch (p.*) {
                    .all_of, .batch_all_of, .ordered => |c| &c[a.path[k]],
                    .threshold => |t| blk: {
                        if (t.k != t.nodes.len) return false;
                        break :blk &t.nodes[a.path[k]];
                    },
                    .any_of, .leaf => return false,
                };
            }
            return true;
        }
        cur = switch (cur.*) {
            .all_of => |c| &c[a.path[d]],
            .batch_all_of => |c| &c[a.path[d]],
            .any_of => |c| &c[a.path[d]],
            .ordered => |c| &c[a.path[d]],
            .threshold => |t| &t.nodes[a.path[d]],
            .leaf => return false,
        };
    }
    return false;
}

/// 5-bit category mask + 1-bit for ">= 2 factors" -> 6-bit DP?
/// Spec says: 3-bit mask DP (knowledge/possession/inherence or general category mask + factor count).
/// We use a 32-bit mask for 5 categories + 1 bit for single-factor tracking (64 states total).
const DpState = u64; // bit i (0..31) for category mask i, or bitmask of (cat_mask << 1 | multi_factor_bit)

fn evalMinAssurance(node: *const PolicyNode, registry: *const registry_mod.FactorRegistry, min_cats: u8, allow_single: bool) bool {
    const MaskSet = struct {
        // 32 category masks * 2 (single_factor=0, multi_factor=1) = 64 bits
        bits: u64 = 0,

        fn fromLeaf(cats: types.CategorySet) @This() {
            const raw: u5 = @truncate(@as(u8, @bitCast(cats)) & 0x1F);
            const idx: u6 = (@as(u6, raw) << 1) | 0;
            return .{ .bits = @as(u64, 1) << idx };
        }

        fn combineOr(a: @This(), b: @This()) @This() {
            return .{ .bits = a.bits | b.bits };
        }

        fn combineAnd(a: @This(), b: @This()) @This() {
            var res: u64 = 0;
            for (0..64) |i| {
                if ((a.bits & (@as(u64, 1) << @intCast(i))) == 0) continue;
                const ca: u5 = @intCast(i >> 1);
                for (0..64) |j| {
                    if ((b.bits & (@as(u64, 1) << @intCast(j))) == 0) continue;
                    const cb: u5 = @intCast(j >> 1);
                    const merged: u6 = (@as(u6, ca | cb) << 1) | 1;
                    res |= @as(u64, 1) << merged;
                }
            }
            return .{ .bits = res };
        }

        fn satisfies(self: @This(), req_cats: u8, allow_1: bool) bool {
            for (0..64) |i| {
                if ((self.bits & (@as(u64, 1) << @intCast(i))) == 0) continue;
                const cats: u5 = @intCast(i >> 1);
                const is_multi = (i & 1) == 1;
                if (@popCount(cats) < req_cats) return false;
                if (!allow_1 and !is_multi) return false;
            }
            return self.bits != 0;
        }
    };

    const eval = struct {
        fn run(n: *const PolicyNode, reg: *const registry_mod.FactorRegistry) errors.MfaError!MaskSet {
            switch (n.*) {
                .leaf => |l| {
                    const desc = reg.get(l.factor_id) orelse return errors.MfaError.InvalidPolicy;
                    return MaskSet.fromLeaf(desc.categories);
                },
                .all_of, .batch_all_of, .ordered => |children| {
                    var acc = try run(&children[0], reg);
                    for (children[1..]) |*c| {
                        acc = acc.combineAnd(try run(c, reg));
                    }
                    return acc;
                },
                .any_of => |children| {
                    var acc = MaskSet{};
                    for (children) |*c| {
                        acc = acc.combineOr(try run(c, reg));
                    }
                    return acc;
                },
                .threshold => |th| {
                    // DP over k-of-n children
                    var dp: [types.max_policy_leaves + 1]MaskSet = undefined;
                    dp[0] = .{ .bits = 1 }; // empty set: 0 cats, 0 factors
                    for (1..th.k + 1) |i| dp[i] = .{};

                    for (th.nodes) |*child| {
                        const cs = try run(child, reg);
                        var j: usize = th.k;
                        while (j >= 1) : (j -= 1) {
                            if (j == 1) {
                                dp[1] = dp[1].combineOr(cs);
                            } else if (dp[j - 1].bits != 0) {
                                dp[j] = dp[j].combineOr(dp[j - 1].combineAnd(cs));
                            }
                        }
                    }
                    return dp[th.k];
                },
            }
        }
    };

    const res = eval.run(node, registry) catch return false;
    return res.satisfies(min_cats, allow_single);
}

pub fn worstCaseStateSize(chain: SecurityChain, limits: types.SessionLimits) usize {
    const helper = struct {
        fn sizeOf(node: *const PolicyNode, lim: types.SessionLimits) usize {
            return switch (node.*) {
                .leaf => lim.max_derived_ctx_len + lim.max_claims_len + 256,
                .all_of, .batch_all_of, .ordered => |children| blk: {
                    var sum: usize = 0;
                    for (children) |*c| sum += sizeOf(c, lim);
                    break :blk sum;
                },
                .any_of => |children| blk: {
                    var max_c: usize = 0;
                    for (children) |*c| max_c = @max(max_c, sizeOf(c, lim));
                    break :blk max_c;
                },
                .threshold => |th| blk: {
                    var sizes: [types.max_policy_leaves]usize = undefined;
                    const n = @min(th.nodes.len, types.max_policy_leaves);
                    for (th.nodes[0..n], 0..) |*c, idx| {
                        sizes[idx] = sizeOf(c, lim);
                    }
                    std.sort.pdq(usize, sizes[0..n], {}, std.sort.desc(usize));
                    var sum: usize = 0;
                    const take = @min(@as(usize, th.k), n);
                    for (sizes[0..take]) |s| sum += s;
                    break :blk sum;
                },
            };
        }
    };
    return 1024 + helper.sizeOf(&chain.root, limits) +
        @as(usize, limits.max_active_challenges) * (limits.max_challenge_state_len + 128);
}

pub fn validatePolicy(
    env: PolicyEnv,
    chain: SecurityChain,
    assurance: types.AssurancePolicy,
    enrollment_mode: types.EnrollmentMode,
    limits: types.SessionLimits,
) errors.MfaError!void {
    if (chain.action_scope.len == 0 or chain.action_scope.len > limits.max_scope_len) {
        return errors.MfaError.InvalidPolicy;
    }

    var effective_assurance = assurance;
    if (isReservedScope(chain.action_scope)) {
        effective_assurance.min_categories = @max(effective_assurance.min_categories, 2);
        effective_assurance.allow_single_factor = false;
    }

    var ctx = ValidateCtx{
        .env = env,
        .assurance = effective_assurance,
        .enrollment_mode = enrollment_mode,
        .limits = limits,
    };
    var path: [types.max_policy_depth]usize = undefined;
    _ = try validateNode(&ctx, &chain.root, 0, false, &path);

    // Validate reads_ctx_from dependencies
    for (ctx.leaves[0..ctx.leaf_count]) |consumer| {
        for (consumer.reads_ctx_from) |dep| {
            var producer_opt: ?LeafInfo = null;
            for (ctx.leaves[0..ctx.leaf_count]) |cand| {
                if (std.mem.eql(u8, cand.factor_id, dep.factor_id)) {
                    producer_opt = cand;
                    break;
                }
            }
            const producer = producer_opt orelse return errors.MfaError.InvalidPolicy;
            if (!findOrderedAncestor(&chain.root, producer, consumer, dep.required)) {
                return errors.MfaError.InvalidPolicy;
            }
        }
    }

    if (!evalMinAssurance(&chain.root, env.registry, effective_assurance.min_categories, effective_assurance.allow_single_factor)) {
        return errors.MfaError.WeakBinding;
    }

    if (limits.max_sealed_blob_len < worstCaseStateSize(chain, limits)) {
        return errors.MfaError.LimitExceeded;
    }
}

pub fn requireNotWeaker(
    reference: SecurityChain,
    candidate: SecurityChain,
    registry: *const registry_mod.FactorRegistry,
) errors.MfaError!void {
    const MaskSet = struct {
        bits: u64 = 0,
        fn fromLeaf(cats: types.CategorySet) @This() {
            const raw: u5 = @truncate(@as(u8, @bitCast(cats)) & 0x1F);
            const idx: u6 = (@as(u6, raw) << 1) | 0;
            return .{ .bits = @as(u64, 1) << idx };
        }
        fn combineOr(a: @This(), b: @This()) @This() {
            return .{ .bits = a.bits | b.bits };
        }
        fn combineAnd(a: @This(), b: @This()) @This() {
            var res: u64 = 0;
            for (0..64) |i| {
                if ((a.bits & (@as(u64, 1) << @intCast(i))) == 0) continue;
                const ca: u5 = @intCast(i >> 1);
                for (0..64) |j| {
                    if ((b.bits & (@as(u64, 1) << @intCast(j))) == 0) continue;
                    const cb: u5 = @intCast(j >> 1);
                    const merged: u6 = (@as(u6, ca | cb) << 1) | 1;
                    res |= @as(u64, 1) << merged;
                }
            }
            return .{ .bits = res };
        }
        fn satisfies(self: @This(), req_cats: u8, allow_1: bool) bool {
            for (0..64) |i| {
                if ((self.bits & (@as(u64, 1) << @intCast(i))) == 0) continue;
                const cats: u5 = @intCast(i >> 1);
                const is_multi = (i & 1) == 1;
                if (@popCount(cats) < req_cats) return false;
                if (!allow_1 and !is_multi) return false;
            }
            return self.bits != 0;
        }
        fn minGuarantee(self: @This()) struct { min_cats: u8, requires_multi: bool } {
            var min_cats: u8 = 255;
            var requires_multi = true;
            for (0..64) |i| {
                if ((self.bits & (@as(u64, 1) << @intCast(i))) == 0) continue;
                const cats: u5 = @intCast(i >> 1);
                const is_multi = (i & 1) == 1;
                min_cats = @min(min_cats, @as(u8, @popCount(cats)));
                if (!is_multi) requires_multi = false;
            }
            if (min_cats == 255) min_cats = 0;
            return .{ .min_cats = min_cats, .requires_multi = requires_multi };
        }
    };
    const eval = struct {
        fn run(n: *const PolicyNode, reg: *const registry_mod.FactorRegistry) errors.MfaError!MaskSet {
            switch (n.*) {
                .leaf => |l| {
                    const desc = reg.get(l.factor_id) orelse return errors.MfaError.InvalidPolicy;
                    return MaskSet.fromLeaf(desc.categories);
                },
                .all_of, .batch_all_of, .ordered => |children| {
                    if (children.len == 0) return errors.MfaError.InvalidPolicy;
                    var acc = try run(&children[0], reg);
                    for (children[1..]) |*c| {
                        acc = acc.combineAnd(try run(c, reg));
                    }
                    return acc;
                },
                .any_of => |children| {
                    if (children.len == 0) return errors.MfaError.InvalidPolicy;
                    var acc = MaskSet{};
                    for (children) |*c| {
                        acc = acc.combineOr(try run(c, reg));
                    }
                    return acc;
                },
                .threshold => |th| {
                    if (th.nodes.len == 0 or th.k == 0 or th.k > th.nodes.len) return errors.MfaError.InvalidPolicy;
                    var dp: [types.max_policy_leaves + 1]MaskSet = undefined;
                    dp[0] = .{ .bits = 1 };
                    for (1..th.k + 1) |i| dp[i] = .{};
                    for (th.nodes) |*child| {
                        const cs = try run(child, reg);
                        var j: usize = th.k;
                        while (j >= 1) : (j -= 1) {
                            if (j == 1) {
                                dp[1] = dp[1].combineOr(cs);
                            } else if (dp[j - 1].bits != 0) {
                                dp[j] = dp[j].combineOr(dp[j - 1].combineAnd(cs));
                            }
                        }
                    }
                    return dp[th.k];
                },
            }
        }
    };

    const ref_set = try eval.run(&reference.root, registry);
    const cand_set = try eval.run(&candidate.root, registry);
    const ref_min = ref_set.minGuarantee();
    const req_cats = @max(@as(u8, 2), ref_min.min_cats);
    if (!cand_set.satisfies(req_cats, false)) {
        return errors.MfaError.WeakBinding;
    }
}
