const std = @import("std");
const types = @import("types.zig");
const ports = @import("ports.zig");
const policy = @import("policy.zig");
const registry_mod = @import("registry.zig");

pub const FingerprintOptions = struct {
    outcome_class: types.OutcomeClass = .terminal,
    binding_mode: types.BindingMode = .bound,
    assurance: types.AssurancePolicy = .{},
};

fn writeU32Le(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, val, .little);
    try buf.appendSlice(allocator, &bytes);
}

fn writeLp(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) !void {
    try writeU32Le(buf, allocator, @intCast(data.len));
    try buf.appendSlice(allocator, data);
}

fn encodeNode(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, node: policy.PolicyNode, registry: *const registry_mod.FactorRegistry) !void {
    switch (node) {
        .leaf => |l| {
            try buf.append(allocator, 0x01);
            try writeLp(buf, allocator, l.factor_id);
            if (registry.get(l.factor_id)) |d| {
                const cats: u8 = @as(u8, @bitCast(d.categories)) & 0x07;
                var leaf_flags: u8 = 0;
                if (d.requires_challenge) leaf_flags |= 0x01;
                if (d.statefulness == .stateful) leaf_flags |= 0x02;
                if (d.supports_batch) leaf_flags |= 0x04;
                if (d.is_recovery) leaf_flags |= 0x08;
                try buf.append(allocator, cats);
                try buf.append(allocator, leaf_flags);
                try writeLp(buf, allocator, d.implementation_id);
            } else {
                try buf.append(allocator, 0);
                try buf.append(allocator, 0);
                try writeLp(buf, allocator, "");
            }
            try writeU32Le(buf, allocator, @intCast(l.reads_ctx_from.len));
            for (l.reads_ctx_from) |dep| {
                try writeLp(buf, allocator, dep.factor_id);
                try buf.append(allocator, @intFromBool(dep.required));
            }
        },
        .all_of => |children| {
            try buf.append(allocator, 0x02);
            try writeU32Le(buf, allocator, @intCast(children.len));
            for (children) |c| try encodeNode(buf, allocator, c, registry);
        },
        .batch_all_of => |children| {
            try buf.append(allocator, 0x03);
            try writeU32Le(buf, allocator, @intCast(children.len));
            for (children) |c| try encodeNode(buf, allocator, c, registry);
        },
        .any_of => |children| {
            try buf.append(allocator, 0x04);
            try writeU32Le(buf, allocator, @intCast(children.len));
            for (children) |c| try encodeNode(buf, allocator, c, registry);
        },
        .threshold => |th| {
            try buf.append(allocator, 0x05);
            try writeU32Le(buf, allocator, th.k);
            try buf.append(allocator, @intFromBool(th.distinct_categories));
            try writeU32Le(buf, allocator, @intCast(th.nodes.len));
            for (th.nodes) |c| try encodeNode(buf, allocator, c, registry);
        },
        .ordered => |children| {
            try buf.append(allocator, 0x06);
            try writeU32Le(buf, allocator, @intCast(children.len));
            for (children) |c| try encodeNode(buf, allocator, c, registry);
        },
    }
}

pub fn encodePolicy(
    allocator: std.mem.Allocator,
    registry: *const registry_mod.FactorRegistry,
    chain: policy.SecurityChain,
    opts: FingerprintOptions,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.append(allocator, 6); // layout version
    try writeLp(&buf, allocator, chain.action_scope);
    try buf.append(allocator, @intFromEnum(opts.outcome_class));
    try buf.append(allocator, @intFromEnum(opts.binding_mode));
    try buf.append(allocator, opts.assurance.min_categories);

    var assurance_flags: u8 = 0;
    if (opts.assurance.allow_single_factor) assurance_flags |= 0x01;
    if (opts.assurance.allow_unordered_all_of) assurance_flags |= 0x02;
    if (opts.assurance.allow_stateful_in_batch) assurance_flags |= 0x04;
    try buf.append(allocator, assurance_flags);

    try encodeNode(&buf, allocator, chain.root, registry);
    return buf.toOwnedSlice(allocator);
}

pub fn policyFingerprint(
    allocator: std.mem.Allocator,
    hash_port: ports.HashPort,
    registry: *const registry_mod.FactorRegistry,
    chain: policy.SecurityChain,
    opts: FingerprintOptions,
) ![32]u8 {
    const enc = try encodePolicy(allocator, registry, chain, opts);
    defer allocator.free(enc);

    const alg = hash_port.algorithmId();
    var alg_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &alg_len, @intCast(alg.len), .little);

    return hash_port.hash(&.{
        "parabellum_mfa/policy/v6\x00",
        &alg_len,
        alg,
        enc,
    });
}

pub fn composedPolicyFingerprint(
    hash_port: ports.HashPort,
    fp_inter: [32]u8,
    fp_term: [32]u8,
) [32]u8 {
    const alg = hash_port.algorithmId();
    var alg_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &alg_len, @intCast(alg.len), .little);
    return hash_port.hash(&.{
        "parabellum_mfa/composed_policy/v6\x00",
        &alg_len,
        alg,
        &fp_inter,
        &fp_term,
    });
}

pub fn bindingHash(hash_port: ports.HashPort, binding: []const u8) [32]u8 {
    const alg = hash_port.algorithmId();
    var alg_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &alg_len, @intCast(alg.len), .little);
    return hash_port.hash(&.{
        "parabellum_mfa/binding/v6\x00",
        &alg_len,
        alg,
        binding,
    });
}

pub fn composedSessionId(
    hash_port: ports.HashPort,
    inter_sid: []const u8,
    term_sid: []const u8,
) [64]u8 {
    const alg = hash_port.algorithmId();
    var alg_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &alg_len, @intCast(alg.len), .little);
    var inter_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &inter_len, @intCast(inter_sid.len), .little);
    var term_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &term_len, @intCast(term_sid.len), .little);
    const digest = hash_port.hash(&.{
        "parabellum_mfa/composed_session/v6\x00",
        &alg_len,
        alg,
        &inter_len,
        inter_sid,
        &term_len,
        term_sid,
    });
    return std.fmt.bytesToHex(digest, .lower);
}

test "policyFingerprint is deterministic and sensitive to options" {
    const DummyHash = struct {
        fn algorithmId(_: *anyopaque) []const u8 {
            return "test-sha256";
        }
        fn hash(_: *anyopaque, parts: []const []const u8) [32]u8 {
            var acc: u8 = 0x5A;
            var idx: usize = 0;
            for (parts) |part| {
                for (part) |b| {
                    acc ^= b +% @as(u8, @truncate(idx));
                    idx += 1;
                }
            }
            return @splat(acc);
        }
        const vtable = ports.HashPort.VTable{
            .algorithmId = algorithmId,
            .hash = hash,
        };
        fn port(self: *@This()) ports.HashPort {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
    var h = DummyHash{};
    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{});
    defer reg.deinit();

    const chain = policy.SecurityChain{
        .action_scope = "login",
        .root = .{ .leaf = .{ .factor_id = "pwd" } },
    };

    const fp1 = try policyFingerprint(std.testing.allocator, h.port(), &reg, chain, .{});
    const fp2 = try policyFingerprint(std.testing.allocator, h.port(), &reg, chain, .{});
    const fp3 = try policyFingerprint(std.testing.allocator, h.port(), &reg, chain, .{ .outcome_class = .intermediate });

    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
    try std.testing.expect(!std.mem.eql(u8, &fp1, &fp3));
}

test "Annex A.4 v6 test vectors match encodePolicy and sha256 fingerprints" {
    const Sha256Port = struct {
        fn algorithmId(_: *anyopaque) []const u8 {
            return "sha256";
        }
        fn hash(_: *anyopaque, parts: []const []const u8) [32]u8 {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            for (parts) |p| h.update(p);
            var out: [32]u8 = undefined;
            h.final(&out);
            return out;
        }
        const vtable = ports.HashPort.VTable{ .algorithmId = algorithmId, .hash = hash };
        fn port(self: *@This()) ports.HashPort {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
    const MakeVerifier = struct {
        desc: types.FactorDescriptor,
        fn describe(ptr: *anyopaque) types.FactorDescriptor {
            return @as(*@This(), @ptrCast(@alignCast(ptr))).desc;
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

    var v_pwd = MakeVerifier{ .desc = .{ .factor_id = "pwd", .categories = .{ .knowledge = true }, .implementation_id = "argon2id", .supports_batch = true } };
    var v_totp = MakeVerifier{ .desc = .{ .factor_id = "totp", .categories = .{ .possession = true }, .implementation_id = "rfc6238", .requires_challenge = true, .supports_batch = true } };
    var v_web = MakeVerifier{ .desc = .{ .factor_id = "webauthn", .categories = .{ .possession = true }, .implementation_id = "fido2", .requires_challenge = true } };
    var v_face = MakeVerifier{ .desc = .{ .factor_id = "face", .categories = .{ .inherence = true }, .implementation_id = "biometric", .requires_challenge = true } };
    var v_rec = MakeVerifier{ .desc = .{ .factor_id = "rec", .categories = .{ .possession = true }, .implementation_id = "recovery-v1", .statefulness = .stateful, .is_recovery = true } };

    const alloc = std.testing.allocator;
    var reg = try registry_mod.FactorRegistry.init(alloc, &.{
        v_pwd.verifier(),
        v_totp.verifier(),
        v_web.verifier(),
        v_face.verifier(),
        v_rec.verifier(),
    });
    defer reg.deinit();

    var sha = Sha256Port{};
    const json_bytes = std.Io.Dir.cwd().readFileAlloc(std.testing.io, "lib/mfa/testdata/vectors_v6.json", alloc, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "mfa/testdata/vectors_v6.json", alloc, .limited(1024 * 1024)),
        else => return err,
    };
    defer alloc.free(json_bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, json_bytes, .{});
    defer parsed.deinit();

    const ParseHelper = struct {
        fn buildNode(a: std.mem.Allocator, val: std.json.Value) !policy.PolicyNode {
            const obj = val.object;
            const kind = obj.get("kind").?.string;
            if (std.mem.eql(u8, kind, "leaf")) {
                const fid = obj.get("factor_id").?.string;
                var deps: []const policy.ContextDependency = &.{};
                if (obj.get("reads_ctx_from")) |deps_val| {
                    const arr = deps_val.array.items;
                    const slice = try a.alloc(policy.ContextDependency, arr.len);
                    for (arr, 0..) |d, i| {
                        slice[i] = .{
                            .factor_id = d.object.get("factor_id").?.string,
                            .required = if (d.object.get("required")) |r| r.bool else true,
                        };
                    }
                    deps = slice;
                }
                return .{ .leaf = .{ .factor_id = fid, .reads_ctx_from = deps } };
            }
            const arr = obj.get("nodes").?.array.items;
            const children = try a.alloc(policy.PolicyNode, arr.len);
            for (arr, 0..) |c, i| children[i] = try buildNode(a, c);
            if (std.mem.eql(u8, kind, "all_of")) return .{ .all_of = children };
            if (std.mem.eql(u8, kind, "batch_all_of")) return .{ .batch_all_of = children };
            if (std.mem.eql(u8, kind, "any_of")) return .{ .any_of = children };
            if (std.mem.eql(u8, kind, "ordered")) return .{ .ordered = children };
            if (std.mem.eql(u8, kind, "threshold")) {
                return .{ .threshold = .{
                    .k = @intCast(obj.get("k").?.integer),
                    .distinct_categories = if (obj.get("distinct_categories")) |dc| dc.bool else false,
                    .nodes = children,
                } };
            }
            return error.InvalidVector;
        }
    };

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    try std.testing.expect(parsed.value.array.items.len >= 8);
    for (parsed.value.array.items) |vec| {
        const obj = vec.object;
        const root = try ParseHelper.buildNode(arena.allocator(), obj.get("root").?);
        const chain = policy.SecurityChain{
            .action_scope = obj.get("action_scope").?.string,
            .root = root,
        };
        const oc: types.OutcomeClass = if (std.mem.eql(u8, obj.get("outcome_class").?.string, "terminal")) .terminal else .intermediate;
        const bm: types.BindingMode = if (std.mem.eql(u8, obj.get("binding_mode").?.string, "bound")) .bound else .unbound;
        const opts = FingerprintOptions{
            .outcome_class = oc,
            .binding_mode = bm,
            .assurance = .{
                .min_categories = @intCast(obj.get("min_categories").?.integer),
                .allow_single_factor = if (obj.get("allow_single_factor")) |v| v.bool else false,
                .allow_unordered_all_of = if (obj.get("allow_unordered_all_of")) |v| v.bool else false,
                .allow_stateful_in_batch = if (obj.get("allow_stateful_in_batch")) |v| v.bool else false,
            },
        };
        const enc = try encodePolicy(alloc, &reg, chain, opts);
        defer alloc.free(enc);
        const enc_hex = try std.fmt.allocPrint(alloc, "{x}", .{enc});
        defer alloc.free(enc_hex);
        try std.testing.expectEqualStrings(obj.get("enc_hex").?.string, enc_hex);

        const fp = try policyFingerprint(alloc, sha.port(), &reg, chain, opts);
        const fp_hex = std.fmt.bytesToHex(fp, .lower);
        try std.testing.expectEqualStrings(obj.get("sha256_hex").?.string, &fp_hex);
    }
}
