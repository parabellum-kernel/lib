const std = @import("std");
const builtin = @import("builtin");
const primitives = @import("primitives.zig");
const ports = @import("ports.zig");
const types = @import("types.zig");
const errors = @import("errors.zig");
const registry_mod = @import("registry.zig");
const policy = @import("policy.zig");
const session = @import("session.zig");
const engine = @import("engine.zig");
const verify = @import("verify.zig");
const helpers = @import("helpers.zig");

pub const MockSealer = if (builtin.is_test) struct {
    pub fn sealer(self: *@This()) ports.StateSealer {
        return .{ .ptr = self, .vtable = &vtable };
    }
    fn tagOf(aad: []const u8, pt: []const u8) u32 {
        var h: u32 = 2166136261;
        for (aad) |b| h = (h ^ b) *% 16777619;
        h ^= 0xFF;
        for (pt) |b| h = (h ^ b) *% 16777619;
        return h;
    }
    fn seal(_: *anyopaque, alloc: std.mem.Allocator, _: ports.RandomPort, pt: []const u8, aad: []const u8) ports.StateSealer.SealerError![]u8 {
        var out = alloc.alloc(u8, 4 + aad.len + pt.len + 4) catch return error.OutOfMemory;
        std.mem.writeInt(u32, out[0..4], @intCast(aad.len), .little);
        @memcpy(out[4 .. 4 + aad.len], aad);
        @memcpy(out[4 + aad.len .. 4 + aad.len + pt.len], pt);
        std.mem.writeInt(u32, out[4 + aad.len + pt.len ..][0..4], tagOf(aad, pt), .little);
        return out;
    }
    fn open(_: *anyopaque, alloc: std.mem.Allocator, ct: []const u8, aad: []const u8) ports.StateSealer.SealerError![]u8 {
        if (ct.len < 8) return error.OpenFailed;
        const aad_len = std.mem.readInt(u32, ct[0..4], .little);
        if (4 + aad_len + 4 > ct.len) return error.OpenFailed;
        if (!std.mem.eql(u8, ct[4 .. 4 + aad_len], aad)) return error.OpenFailed;
        const pt = ct[4 + aad_len .. ct.len - 4];
        const expected = std.mem.readInt(u32, ct[ct.len - 4 ..][0..4], .little);
        if (expected != tagOf(aad, pt)) return error.OpenFailed;
        return alloc.dupe(u8, pt) catch return error.OutOfMemory;
    }
    const vtable = ports.StateSealer.VTable{ .seal = seal, .open = open };
} else @compileError("MockSealer is only available in test builds");

pub fn hash_conformance(hash_port: ports.HashPort) !void {
    const out1 = hash_port.hash(&.{"hello"});
    const out2 = hash_port.hash(&.{"hello"});
    try std.testing.expectEqualSlices(u8, &out1, &out2);

    const out3 = hash_port.hash(&.{"hello!"});
    try std.testing.expect(!std.mem.eql(u8, &out1, &out3));

    const out_split = hash_port.hash(&.{ "ab", "c" });
    const out_split2 = hash_port.hash(&.{ "a", "bc" });
    try std.testing.expectEqualSlices(u8, &out_split, &out_split2);

    const alg = hash_port.algorithmId();
    if (std.mem.eql(u8, alg, "sha256")) {
        const abc_expected = [_]u8{
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        };
        const got = hash_port.hash(&.{"abc"});
        try std.testing.expectEqualSlices(u8, &abc_expected, &got);
    } else if (std.mem.eql(u8, alg, "sha3-256")) {
        const abc_expected = [_]u8{
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        };
        const got = hash_port.hash(&.{"abc"});
        try std.testing.expectEqualSlices(u8, &abc_expected, &got);
    } else if (std.mem.eql(u8, alg, "blake3")) {
        const abc_expected = [_]u8{
            0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33,
            0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
            0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03,
            0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
        };
        const got = hash_port.hash(&.{"abc"});
        try std.testing.expectEqualSlices(u8, &abc_expected, &got);
    }
}

pub fn random_sanity(random: ports.RandomPort) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try random.bytes(&a);
    try random.bytes(&b);

    const zeros: [32]u8 = @splat(0);
    try std.testing.expect(!std.mem.eql(u8, &a, &zeros));
    try std.testing.expect(!std.mem.eql(u8, &b, &zeros));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));

    var all_same = true;
    for (a[1..]) |byte| {
        if (byte != a[0]) {
            all_same = false;
            break;
        }
    }
    try std.testing.expect(!all_same);
}

pub fn sealer_conformance(sealer: ports.StateSealer, random: ports.RandomPort, allocator: std.mem.Allocator) !void {
    const blob = try sealer.seal(allocator, random, "secret-data", "aad-1");
    defer allocator.free(blob);

    const pt = try sealer.open(allocator, blob, "aad-1");
    defer allocator.free(pt);
    try std.testing.expectEqualStrings("secret-data", pt);

    try std.testing.expectError(error.OpenFailed, sealer.open(allocator, blob, "aad-2"));
    try std.testing.expectError(error.OpenFailed, sealer.open(allocator, &.{}, "aad-1"));
    if (blob.len > 1) {
        try std.testing.expectError(error.OpenFailed, sealer.open(allocator, blob[0 .. blob.len - 1], "aad-1"));
        const tampered = try allocator.dupe(u8, blob);
        defer allocator.free(tampered);
        tampered[tampered.len - 1] ^= 0xFF;
        try std.testing.expectError(error.OpenFailed, sealer.open(allocator, tampered, "aad-1"));
    }
}

pub fn grant_conformance(
    signer: ports.GrantSigner,
    verifier: ports.GrantVerifier,
    replay_guard: ?ports.ReplayGuard,
    allocator: std.mem.Allocator,
    now_unix_s: i64,
) !void {
    const sentinel = "SENTINEL_DERIVED_CTX_SECRET";
    const factors = try allocator.alloc(session.FactorOutput, 1);
    factors[0] = .{
        .factor_id = try allocator.dupe(u8, "pwd"),
        .verified_at = now_unix_s,
        .derived_ctx = try allocator.dupe(u8, sentinel),
        .contributing = true,
    };
    var outcome = session.ChainOutcome{
        .subject_id = try allocator.dupe(u8, "user-1"),
        .action_scope = try allocator.dupe(u8, "login"),
        .session_id = try allocator.dupe(u8, "sess-1"),
        .policy_fingerprint = @splat(0x42),
        .binding_mode = .bound,
        .binding_hash = @splat(0x24),
        .max_grant_ttl_s = 300,
        .completed_at = now_unix_s,
        .expires_at = now_unix_s + 300,
        .categories_mask = .{ .knowledge = true, .possession = true },
        .used_recovery = false,
        .satisfied_factors = factors,
    };
    defer outcome.deinit(allocator, allocator);

    const tok = try signer.seal(allocator, &outcome, .{ .ttl_s = 120, .audience = "api.example" });
    defer allocator.free(tok);

    try std.testing.expect(std.mem.indexOf(u8, tok, sentinel) == null);

    const expected_single = [_][32]u8{outcome.policy_fingerprint};
    const expected_multi = [_][32]u8{ @splat(0x01), outcome.policy_fingerprint };
    const wrong_policies = [_][32]u8{@splat(0x99)};

    var verified = try verifier.open(allocator, tok, "api.example", &expected_single, now_unix_s + 10);
    defer verified.deinit(allocator);
    try std.testing.expectEqualStrings("user-1", verified.subject_id);
    try std.testing.expectEqualStrings("login", verified.action_scope);

    var verified_multi = try verifier.open(allocator, tok, "api.example", &expected_multi, now_unix_s + 10);
    defer verified_multi.deinit(allocator);

    try std.testing.expectError(error.InvalidAudience, verifier.open(allocator, tok, "wrong.example", &expected_single, now_unix_s + 10));
    try std.testing.expectError(error.Expired, verifier.open(allocator, tok, "api.example", &expected_single, now_unix_s + 500));
    try std.testing.expectError(error.PolicyMismatch, verifier.open(allocator, tok, "api.example", &wrong_policies, now_unix_s + 10));

    if (tok.len > 0) {
        const bad = try allocator.dupe(u8, tok);
        defer allocator.free(bad);
        bad[bad.len - 1] ^= 0x01;
        try std.testing.expectError(error.InvalidSignature, verifier.open(allocator, bad, "api.example", &expected_single, now_unix_s + 10));
    }

    if (replay_guard) |rg| {
        const first = try rg.markUsed(verified.jti, verified.exp);
        try std.testing.expect(first == .fresh);
        const second = try rg.markUsed(verified.jti, verified.exp);
        try std.testing.expect(second == .replayed);
    }
}

pub fn malformed_input_fuzz(sealer: ports.StateSealer, random: ports.RandomPort, allocator: std.mem.Allocator) !void {
    const junk_inputs = [_][]const u8{
        "",
        "x",
        "\x00\x00\x00\x00",
        "truncated-malformed-blob-data",
    };
    for (junk_inputs) |blob| {
        try std.testing.expectError(errors.MfaError.InvalidSessionState, session.SessionState.open(allocator, allocator, sealer, blob, .{
            .session_id = "s",
            .policy_fingerprint = @splat(0),
            .expected_version = 0,
        }, 4096));
    }
    // Valid seal with truncated plaintext inside MockSealer
    const bad_pt = try sealer.seal(allocator, random, "\x05\x00\x00\x00ab", "aad");
    defer allocator.free(bad_pt);
    try std.testing.expectError(errors.MfaError.InvalidSessionState, session.SessionState.open(allocator, allocator, sealer, bad_pt, .{
        .session_id = "s",
        .policy_fingerprint = @splat(0),
        .expected_version = 0,
    }, 4096));
}

pub fn lazy_uniformity(
    env: engine.EngineEnv,
    chain: policy.SecurityChain,
    meta: engine.CallMeta,
    enrolled_factor: []const u8,
    unenrolled_factor: []const u8,
) !void {
    var s1_res = try engine.startChain(env, "user-lazy", chain, meta, .{ .enrollment_mode = .lazy_on_challenge });
    defer s1_res.deinit(env.allocator, env.secret_allocator);
    var s2_res = try engine.startChain(env, "user-lazy", chain, meta, .{ .enrollment_mode = .lazy_on_challenge });
    defer s2_res.deinit(env.allocator, env.secret_allocator);

    var ef1 = try engine.eligibleFactors(env, &s1_res.started, chain, meta);
    defer ef1.deinit(env.allocator);
    try std.testing.expect(ef1.visibility == .structural_only);

    const c1 = engine.requestChallenge(env, &s1_res.started, chain, meta, enrolled_factor);
    const c2 = engine.requestChallenge(env, &s2_res.started, chain, meta, unenrolled_factor);
    if (c1) |v1| {
        var mut1 = v1;
        mut1.deinit(env.allocator);
        if (c2) |v2| {
            var mut2 = v2;
            mut2.deinit(env.allocator);
        } else |e2| {
            return e2;
        }
    } else |e1| {
        try std.testing.expect(e1 != errors.MfaError.FactorNotEnrolled);
        try std.testing.expectError(e1, c2);
    }
}

// ---- Test Helpers ----
const TestRand = struct {
    counter: u8 = 1,
    fn bytes(ptr: *anyopaque, out: []u8) ports.RandomPort.RandomError!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        for (out) |*b| {
            b.* = self.counter;
            self.counter +%= 1;
        }
    }
    const vtable = ports.RandomPort.VTable{ .bytes = bytes };
    fn port(self: *@This()) ports.RandomPort {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const TestHash = struct {
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

const TestVerifier = struct {
    desc: types.FactorDescriptor,
    enrolled: bool = true,
    emit_ctx: ?[]const u8 = null,
    require_ctx: ?[]const u8 = null,
    stateful_counter: bool = false,

    fn describe(ptr: *anyopaque) types.FactorDescriptor {
        return @as(*@This(), @ptrCast(@alignCast(ptr))).desc;
    }
    fn isEnrolled(ptr: *anyopaque, _: []const u8) ports.FactorVerifier.VerifierError!bool {
        return @as(*@This(), @ptrCast(@alignCast(ptr))).enrolled;
    }
    fn issueChallenge(ptr: *anyopaque, ctx: ports.FactorVerifier.ChallengeContext) ports.FactorVerifier.VerifierError!ports.FactorVerifier.ChallengeEmission {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        if (!self.desc.requires_challenge) return .not_applicable;
        if (!self.enrolled and ctx.enrollment_mode == .eager_validate) return .not_enrolled;
        const p = ctx.allocator.dupe(u8, "chal") catch return error.OutOfMemory;
        const cs = ctx.secret_allocator.dupe(u8, "cstate") catch {
            ctx.allocator.free(p);
            return error.OutOfMemory;
        };
        return .{ .challenge = .{ .payload = p, .challenge_state = cs, .ttl_s = 60 } };
    }
    fn verifyFn(ptr: *anyopaque, ctx: ports.FactorVerifier.VerifyContext, proof: []const u8) ports.FactorVerifier.VerifierError!ports.FactorVerifier.VerifyResult {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        if (self.require_ctx) |req| {
            var found = false;
            for (ctx.derived_contexts) |dc| {
                if (std.mem.eql(u8, dc.bytes, req)) found = true;
            }
            if (!found) return .{ .status = .rejected };
        }
        if (!std.mem.eql(u8, proof, "valid")) return .{ .status = .rejected };
        var dctx: ?[]u8 = null;
        if (self.emit_ctx) |ec| {
            dctx = ctx.secret_allocator.dupe(u8, ec) catch return error.OutOfMemory;
        }
        var su: ?[]u8 = null;
        if (self.stateful_counter) {
            su = ctx.secret_allocator.dupe(u8, "v2") catch {
                if (dctx) |d| ctx.secret_allocator.free(d);
                return error.OutOfMemory;
            };
        }
        return .{ .status = .verified, .derived_ctx = dctx, .state_update = su };
    }
    const vtable = ports.FactorVerifier.VTable{
        .describe = describe,
        .isEnrolled = isEnrolled,
        .issueChallenge = issueChallenge,
        .verify = verifyFn,
    };
    fn verifier(self: *@This()) ports.FactorVerifier {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "end-to-end MFA flow: startChain -> submitProof -> takeOutcome" {
    var rnd = TestRand{};
    var h = TestHash{};
    try hash_conformance(h.port());
    try random_sanity(rnd.port());

    var ms = MockSealer{};
    try sealer_conformance(ms.sealer(), rnd.port(), std.testing.allocator);
    try malformed_input_fuzz(ms.sealer(), rnd.port(), std.testing.allocator);

    var v1 = TestVerifier{ .desc = .{ .factor_id = "pwd", .categories = .{ .knowledge = true } } };
    var v2 = TestVerifier{ .desc = .{ .factor_id = "totp", .categories = .{ .possession = true } } };

    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{ v1.verifier(), v2.verifier() });
    defer reg.deinit();

    var store = helpers.StatelessOnlyFactorStore{};
    var tracker = try helpers.InMemoryAttemptTracker.init(std.testing.allocator, true, 5);
    defer tracker.deinit();

    const env = engine.EngineEnv{
        .allocator = std.testing.allocator,
        .random = rnd.port(),
        .registry = &reg,
        .hash = h.port(),
        .tracker = tracker.tracker(),
        .store = store.store(),
    };

    const nodes = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "pwd" } },
        .{ .leaf = .{ .factor_id = "totp" } },
    };
    const chain = policy.SecurityChain{
        .action_scope = "login",
        .root = .{ .ordered = &nodes },
    };

    const meta = engine.CallMeta{
        .now_unix_s = 1000,
        .binding = "0123456789abcdef",
    };

    var start_res = try engine.startChain(env, "user-1", chain, meta, .{});
    defer start_res.deinit(std.testing.allocator, null);
    const state = &start_res.started;

    const r1 = try verify.submitProof(env, state, chain, meta, "pwd", "valid");
    try std.testing.expect(!r1.verified.session_satisfied);

    const r2 = try verify.submitProof(env, state, chain, meta, "totp", "valid");
    try std.testing.expect(r2.verified.session_satisfied);

    var out_res = try verify.takeOutcome(env, state, chain, meta);
    switch (out_res) {
        .terminal => |*t| t.deinit(std.testing.allocator, null),
        .intermediate => |*i| i.deinit(std.testing.allocator, null),
    }
}

test "v6: intermediate+unbound rejected and monotone clock skew enforced" {
    var rnd = TestRand{};
    var h = TestHash{};
    var v1 = TestVerifier{ .desc = .{ .factor_id = "pwd", .categories = .{ .knowledge = true } } };
    var v2 = TestVerifier{ .desc = .{ .factor_id = "totp", .categories = .{ .possession = true } } };
    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{ v1.verifier(), v2.verifier() });
    defer reg.deinit();
    var store = helpers.StatelessOnlyFactorStore{};
    var tracker = try helpers.InMemoryAttemptTracker.init(std.testing.allocator, true, 5);
    defer tracker.deinit();

    const env = engine.EngineEnv{
        .allocator = std.testing.allocator,
        .random = rnd.port(),
        .registry = &reg,
        .hash = h.port(),
        .tracker = tracker.tracker(),
        .store = store.store(),
    };
    const nodes = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "pwd" } },
        .{ .leaf = .{ .factor_id = "totp" } },
    };
    const chain = policy.SecurityChain{ .action_scope = "login", .root = .{ .ordered = &nodes } };

    try std.testing.expectError(errors.MfaError.InvalidPolicy, engine.startChain(env, "u1", chain, .{ .now_unix_s = 100 }, .{
        .outcome_class = .intermediate,
        .binding_mode = .unbound,
    }));

    var start_res = try engine.startChain(env, "u1", chain, .{ .now_unix_s = 100, .binding = "0123456789abcdef" }, .{});
    defer start_res.deinit(std.testing.allocator, null);
    const state = &start_res.started;

    const eff = try engine.advanceClock(state, 99);
    try std.testing.expectEqual(@as(i64, 100), eff);
    try std.testing.expectError(errors.MfaError.ClockSkewDetected, engine.advanceClock(state, 97));
}

test "v6: batch_all_of, allow_stateful_in_batch, and CAS commit" {
    const MemStore = struct {
        ver: u64 = 1,
        fn load(ptr: *anyopaque, _: std.mem.Allocator, _: []const u8, _: []const u8) ports.FactorStateStore.StoreError!ports.FactorStateStore.FactorStateSnapshot {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return .{ .bytes = null, .version = self.ver };
        }
        fn commit(ptr: *anyopaque, _: []const u8, _: []const u8, expected: u64, _: []const u8) ports.FactorStateStore.StoreError!ports.FactorStateStore.CommitResult {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (expected != self.ver) return .conflict;
            self.ver += 1;
            return .committed;
        }
        fn isPersistent(_: *anyopaque) bool {
            return true;
        }
        const vtable = ports.FactorStateStore.VTable{ .load = load, .commit = commit, .isPersistent = isPersistent };
        fn store(self: *@This()) ports.FactorStateStore {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };

    var rnd = TestRand{};
    var h = TestHash{};
    var v1 = TestVerifier{ .desc = .{ .factor_id = "pwd", .categories = .{ .knowledge = true }, .supports_batch = true } };
    var v2 = TestVerifier{ .desc = .{ .factor_id = "rec", .categories = .{ .possession = true }, .supports_batch = true, .statefulness = .stateful, .is_recovery = true }, .stateful_counter = true };
    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{ v1.verifier(), v2.verifier() });
    defer reg.deinit();
    var mstore = MemStore{};
    var tracker = try helpers.InMemoryAttemptTracker.init(std.testing.allocator, true, 5);
    defer tracker.deinit();

    const env = engine.EngineEnv{
        .allocator = std.testing.allocator,
        .random = rnd.port(),
        .registry = &reg,
        .hash = h.port(),
        .tracker = tracker.tracker(),
        .store = mstore.store(),
    };
    const nodes = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "pwd" } },
        .{ .leaf = .{ .factor_id = "rec" } },
    };
    const chain = policy.SecurityChain{ .action_scope = "login", .root = .{ .batch_all_of = &nodes } };
    const meta = engine.CallMeta{ .now_unix_s = 100, .binding = "0123456789abcdef" };

    var start_res = try engine.startChain(env, "u1", chain, meta, .{
        .assurance = .{ .allow_stateful_in_batch = true },
    });
    defer start_res.deinit(std.testing.allocator, null);
    const state = &start_res.started;

    try std.testing.expectError(errors.MfaError.BatchRequired, verify.submitProof(env, state, chain, meta, "pwd", "valid"));
    try std.testing.expectError(errors.MfaError.BatchRequired, verify.submitProofSet(env, state, chain, meta, &.{.{ .factor_id = "pwd", .proof_bytes = "valid" }}));

    const bad_set = try verify.submitProofSet(env, state, chain, meta, &.{
        .{ .factor_id = "pwd", .proof_bytes = "bad" },
        .{ .factor_id = "rec", .proof_bytes = "valid" },
    });
    try std.testing.expect(bad_set == .rejected);

    const ok_set = try verify.submitProofSet(env, state, chain, meta, &.{
        .{ .factor_id = "pwd", .proof_bytes = "valid" },
        .{ .factor_id = "rec", .proof_bytes = "valid" },
    });
    try std.testing.expect(ok_set.verified.session_satisfied);
    try std.testing.expect(state.used_recovery);
    try std.testing.expectEqual(@as(u64, 3), mstore.ver);
}

test "v6: FIFO challenge eviction, reads_ctx_from dominance, and wipe" {
    var rnd = TestRand{};
    var h = TestHash{};
    var v1 = TestVerifier{ .desc = .{ .factor_id = "f1", .categories = .{ .knowledge = true }, .requires_challenge = true }, .emit_ctx = "k1" };
    var v2 = TestVerifier{ .desc = .{ .factor_id = "f2", .categories = .{ .possession = true }, .requires_challenge = true }, .require_ctx = "k1" };
    var v3 = TestVerifier{ .desc = .{ .factor_id = "f3", .categories = .{ .inherence = true }, .requires_challenge = true } };
    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{ v1.verifier(), v2.verifier(), v3.verifier() });
    defer reg.deinit();
    var store = helpers.StatelessOnlyFactorStore{};
    var tracker = try helpers.InMemoryAttemptTracker.init(std.testing.allocator, true, 10);
    defer tracker.deinit();

    var sec_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer sec_arena.deinit();

    const env = engine.EngineEnv{
        .allocator = std.testing.allocator,
        .secret_allocator = sec_arena.allocator(),
        .random = rnd.port(),
        .registry = &reg,
        .hash = h.port(),
        .tracker = tracker.tracker(),
        .store = store.store(),
    };

    // Dominance rejection: required reads_ctx_from through any_of
    const bad_any = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "f1" } },
        .{ .leaf = .{ .factor_id = "f3" } },
    };
    const bad_ord = [_]policy.PolicyNode{
        .{ .any_of = &bad_any },
        .{ .leaf = .{ .factor_id = "f2", .reads_ctx_from = &.{.{ .factor_id = "f1", .required = true }} } },
    };
    const meta = engine.CallMeta{ .now_unix_s = 100, .binding = "0123456789abcdef" };
    try std.testing.expectError(errors.MfaError.InvalidPolicy, engine.startChain(env, "u1", .{
        .action_scope = "login",
        .root = .{ .ordered = &bad_ord },
    }, meta, .{}));

    // Valid ordered chain + FIFO eviction (max_active_challenges = 1)
    const parallel_tail = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "f2", .reads_ctx_from = &.{.{ .factor_id = "f1", .required = true }} } },
        .{ .leaf = .{ .factor_id = "f3" } },
    };
    const good_ord = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "f1" } },
        .{ .all_of = &parallel_tail },
    };
    const chain = policy.SecurityChain{ .action_scope = "login", .root = .{ .ordered = &good_ord } };
    var start_res = try engine.startChain(env, "u1", chain, meta, .{
        .limits = .{ .max_active_challenges = 1 },
        .assurance = .{ .allow_unordered_all_of = true },
    });
    defer start_res.deinit(std.testing.allocator, sec_arena.allocator());
    const state = &start_res.started;

    // f2 is blocked by ordered until f1 is satisfied
    try std.testing.expectError(errors.MfaError.FactorNotReady, engine.requestChallenge(env, state, chain, meta, "f2"));

    var ch1 = try engine.requestChallenge(env, state, chain, meta, "f1");
    ch1.deinit(std.testing.allocator);
    _ = try verify.submitProof(env, state, chain, meta, "f1", "valid");

    // Now f2 is eligible and receives derived_ctx "k1" from f1
    var ch2 = try engine.requestChallenge(env, state, chain, meta, "f2");
    ch2.deinit(std.testing.allocator);
    try std.testing.expect(state.leaf_slots[1].phase == .challenged);

    // Challenging f3 evicts f2's challenge (max_active_challenges = 1)
    var ch3 = try engine.requestChallenge(env, state, chain, meta, "f3");
    ch3.deinit(std.testing.allocator);
    try std.testing.expect(state.leaf_slots[1].phase == .idle);
    try std.testing.expect(state.leaf_slots[2].phase == .challenged);

    // Wipe verification
    var secret_buf = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    primitives.wipe(&secret_buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &secret_buf);
}

test "v6: AdmissionPolicy, EnrollmentVisibilityPolicy, PolicyMigrationHook, requireNotWeaker" {
    const TestAdmission = struct {
        mode: enum { allow, defer_r, deny } = .allow,
        fn evaluate(ptr: *anyopaque, _: ports.AdmissionPolicy.AdmissionRequest) ports.AdmissionPolicy.AdmissionError!ports.AdmissionPolicy.AdmissionDecision {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return switch (self.mode) {
                .allow => .allow,
                .defer_r => .{ .defer_retry = .{ .retry_after_s = 42 } },
                .deny => .deny,
            };
        }
        const vtable = ports.AdmissionPolicy.VTable{ .evaluate = evaluate };
        fn port(self: *@This()) ports.AdmissionPolicy {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
    const TestMigration = struct {
        legacy_chain: policy.SecurityChain,
        legacy_reg: *const registry_mod.FactorRegistry,
        sunset: i64,
        fn resolveLegacy(ptr: *anyopaque, _: [32]u8, _: []const u8, _: i64) ?ports.PolicyMigrationHook.ResolvedLegacyPolicy {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return .{
                .chain = &self.legacy_chain,
                .assurance = .{},
                .outcome_class = .terminal,
                .binding_mode = .bound,
                .legacy_registry = self.legacy_reg,
                .sunset_unix_s = self.sunset,
            };
        }
        const vtable = ports.PolicyMigrationHook.VTable{ .resolveLegacy = resolveLegacy };
        fn port(self: *@This()) ports.PolicyMigrationHook {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };

    var rnd = TestRand{};
    var h = TestHash{};
    var v1 = TestVerifier{ .desc = .{ .factor_id = "pwd", .categories = .{ .knowledge = true } } };
    var v2 = TestVerifier{ .desc = .{ .factor_id = "totp", .categories = .{ .possession = true } } };
    var v3 = TestVerifier{ .desc = .{ .factor_id = "face", .categories = .{ .inherence = true } } };
    var reg = try registry_mod.FactorRegistry.init(std.testing.allocator, &.{ v1.verifier(), v2.verifier(), v3.verifier() });
    defer reg.deinit();
    var store = helpers.StatelessOnlyFactorStore{};
    var tracker = try helpers.InMemoryAttemptTracker.init(std.testing.allocator, true, 10);
    defer tracker.deinit();

    var adm = TestAdmission{ .mode = .defer_r };
    const nodes_2 = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "pwd" } },
        .{ .leaf = .{ .factor_id = "totp" } },
    };
    const nodes_3 = [_]policy.PolicyNode{
        .{ .leaf = .{ .factor_id = "pwd" } },
        .{ .leaf = .{ .factor_id = "totp" } },
        .{ .leaf = .{ .factor_id = "face" } },
    };
    const chain2 = policy.SecurityChain{ .action_scope = "login", .root = .{ .ordered = &nodes_2 } };
    const chain3 = policy.SecurityChain{ .action_scope = "login", .root = .{ .ordered = &nodes_3 } };

    // requireNotWeaker rejects 2-cat candidate against 3-cat reference
    try std.testing.expectError(errors.MfaError.WeakBinding, policy.requireNotWeaker(chain3, chain2, &reg));
    try policy.requireNotWeaker(chain2, chain3, &reg);

    var mig = TestMigration{ .legacy_chain = chain2, .legacy_reg = &reg, .sunset = 500 };
    const env = engine.EngineEnv{
        .allocator = std.testing.allocator,
        .random = rnd.port(),
        .registry = &reg,
        .hash = h.port(),
        .tracker = tracker.tracker(),
        .store = store.store(),
        .admission = adm.port(),
        .migration = mig.port(),
    };
    const meta = engine.CallMeta{ .now_unix_s = 100, .binding = "0123456789abcdef" };

    const rl = try engine.startChain(env, "u1", chain2, meta, .{});
    try std.testing.expectEqual(@as(u64, 42), rl.rate_limited);

    adm.mode = .deny;
    const rej = try engine.startChain(env, "u1", chain2, meta, .{});
    try std.testing.expect(rej == .rejected);

    adm.mode = .allow;
    var start_res = try engine.startChain(env, "u1", chain2, meta, .{});
    defer start_res.deinit(std.testing.allocator, null);
    const state = &start_res.started;

    // Migration within sunset works even when caller passes new chain3
    _ = try engine.resolveActivePolicy(env, state, chain3, 200);
    // Past sunset fails with PolicyMismatch
    try std.testing.expectError(errors.MfaError.PolicyMismatch, engine.resolveActivePolicy(env, state, chain3, 500));
}
