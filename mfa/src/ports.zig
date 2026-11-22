const std = @import("std");
const types = @import("types.zig");
const policy = @import("policy.zig");
const registry_mod = @import("registry.zig");
const session = @import("session.zig");

pub const RandomPort = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const RandomError = error{EntropyUnavailable};

    pub const VTable = struct {
        /// Fills `out` with cryptographically strong random bytes.
        bytes: *const fn (ctx: *anyopaque, out: []u8) RandomError!void,
    };

    pub fn bytes(self: RandomPort, out: []u8) RandomError!void {
        return self.vtable.bytes(self.ptr, out);
    }
};

pub const HashPort = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        algorithmId: *const fn (ctx: *anyopaque) []const u8,
        hash: *const fn (ctx: *anyopaque, parts: []const []const u8) [32]u8,
    };

    pub fn algorithmId(self: HashPort) []const u8 {
        return self.vtable.algorithmId(self.ptr);
    }

    pub fn hash(self: HashPort, parts: []const []const u8) [32]u8 {
        return self.vtable.hash(self.ptr, parts);
    }
};

pub const FactorVerifier = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VerifierError = error{
        OutOfMemory,
        VerifierIoError,
    };

    pub const DerivedContext = struct {
        factor_id: []const u8,
        bytes: []const u8,
    };

    pub const ChallengeContext = struct {
        allocator: std.mem.Allocator,
        secret_allocator: std.mem.Allocator,
        random: RandomPort,
        session_id: []const u8,
        subject_id: []const u8,
        action_scope: []const u8,
        factor_id: []const u8,
        factor_challenge_nonce: [32]u8,
        transcript: [32]u8,
        enrollment_mode: types.EnrollmentMode,
        now_unix_s: i64,
        request_ctx: ?[]const u8 = null,
        derived_contexts: []const DerivedContext = &.{},
    };

    pub const ChallengeEmission = union(enum) {
        not_applicable,
        not_enrolled,
        challenge: struct {
            payload: []u8,
            challenge_state: ?[]u8 = null,
            ttl_s: ?u64 = null,
            decoy: bool = false,
        },
    };

    pub const VerifyContext = struct {
        allocator: std.mem.Allocator,
        secret_allocator: std.mem.Allocator,
        random: RandomPort,
        session_id: []const u8,
        subject_id: []const u8,
        action_scope: []const u8,
        factor_id: []const u8,
        factor_challenge_nonce: ?[32]u8 = null,
        transcript: [32]u8,
        challenge_state: ?[]const u8 = null,
        factor_state: ?[]const u8 = null,
        factor_state_version: u64 = 0,
        enrollment_mode: types.EnrollmentMode,
        now_unix_s: i64,
        request_ctx: ?[]const u8 = null,
        derived_contexts: []const DerivedContext = &.{},
    };

    pub const VerifyStatus = union(enum) {
        verified,
        rejected,
        pending,
        challenge_continue: struct {
            payload: []u8,
            challenge_state: ?[]u8 = null,
            ttl_s: ?u64 = null,
        },
    };

    pub const VerifyResult = struct {
        status: VerifyStatus,
        state_update: ?[]u8 = null,
        derived_ctx: ?[]u8 = null,
        claims: ?[]u8 = null,
    };

    pub const VTable = struct {
        describe: *const fn (ctx: *anyopaque) types.FactorDescriptor,
        isEnrolled: *const fn (ctx: *anyopaque, subject_id: []const u8) VerifierError!bool,
        issueChallenge: *const fn (ctx: *anyopaque, challenge_ctx: ChallengeContext) VerifierError!ChallengeEmission,
        verify: *const fn (ctx: *anyopaque, verify_ctx: VerifyContext, proof_bytes: []const u8) VerifierError!VerifyResult,
    };

    pub fn describe(self: FactorVerifier) types.FactorDescriptor {
        return self.vtable.describe(self.ptr);
    }

    pub fn isEnrolled(self: FactorVerifier, subject_id: []const u8) VerifierError!bool {
        return self.vtable.isEnrolled(self.ptr, subject_id);
    }

    pub fn issueChallenge(self: FactorVerifier, challenge_ctx: ChallengeContext) VerifierError!ChallengeEmission {
        return self.vtable.issueChallenge(self.ptr, challenge_ctx);
    }

    pub fn verify(self: FactorVerifier, verify_ctx: VerifyContext, proof_bytes: []const u8) VerifierError!VerifyResult {
        return self.vtable.verify(self.ptr, verify_ctx, proof_bytes);
    }
};

pub const AttemptTracker = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const TrackerError = error{
        OutOfMemory,
        TrackerUnavailable,
    };

    pub const AttemptOp = enum {
        session_start,
        session_access,
        challenge,
        verify,
    };

    pub const AttemptOutcome = enum {
        session_started,
        verified,
        rejected,
        pending,
        challenge_issued,
        infra_error,
        released,
    };

    pub const AttemptScope = struct {
        subject_id: []const u8,
        factor_id: ?[]const u8 = null,
        session_id: ?[]const u8 = null,
        source_key: ?[]const u8 = null,
        batch_key: ?[]const u8 = null,
    };

    pub const Reservation = struct {
        token: u64,
    };

    pub const ReserveDecision = union(enum) {
        granted: Reservation,
        locked_out: struct {
            retry_after_s: u64,
        },
    };

    pub const VTable = struct {
        reserve: *const fn (ctx: *anyopaque, op: AttemptOp, scope: AttemptScope, now_unix_s: i64) TrackerError!ReserveDecision,
        settle: *const fn (ctx: *anyopaque, reservation: Reservation, outcome: AttemptOutcome, now_unix_s: i64) TrackerError!void,
    };

    pub fn reserve(self: AttemptTracker, op: AttemptOp, scope: AttemptScope, now_unix_s: i64) TrackerError!ReserveDecision {
        return self.vtable.reserve(self.ptr, op, scope, now_unix_s);
    }

    pub fn settle(self: AttemptTracker, reservation: Reservation, outcome: AttemptOutcome, now_unix_s: i64) TrackerError!void {
        return self.vtable.settle(self.ptr, reservation, outcome, now_unix_s);
    }
};

pub const FactorStateStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const StoreError = error{
        OutOfMemory,
        StoreUnavailable,
    };

    pub const FactorStateSnapshot = struct {
        bytes: ?[]u8,
        version: u64,
    };

    pub const CommitResult = enum {
        committed,
        conflict,
    };

    pub const VTable = struct {
        load: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, subject_id: []const u8, factor_id: []const u8) StoreError!FactorStateSnapshot,
        commit: *const fn (ctx: *anyopaque, subject_id: []const u8, factor_id: []const u8, expected_version: u64, state_update: []const u8) StoreError!CommitResult,
        isPersistent: *const fn (ctx: *anyopaque) bool,
    };

    pub fn load(self: FactorStateStore, allocator: std.mem.Allocator, subject_id: []const u8, factor_id: []const u8) StoreError!FactorStateSnapshot {
        return self.vtable.load(self.ptr, allocator, subject_id, factor_id);
    }

    pub fn commit(self: FactorStateStore, subject_id: []const u8, factor_id: []const u8, expected_version: u64, state_update: []const u8) StoreError!CommitResult {
        return self.vtable.commit(self.ptr, subject_id, factor_id, expected_version, state_update);
    }

    pub fn isPersistent(self: FactorStateStore) bool {
        return self.vtable.isPersistent(self.ptr);
    }
};

pub const StateSealer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const SealerError = error{
        OutOfMemory,
        SealFailed,
        OpenFailed,
    };

    pub const VTable = struct {
        seal: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, random: RandomPort, plaintext: []const u8, aad: []const u8) SealerError![]u8,
        open: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, blob: []const u8, aad: []const u8) SealerError![]u8,
    };

    pub fn seal(self: StateSealer, allocator: std.mem.Allocator, random: RandomPort, plaintext: []const u8, aad: []const u8) SealerError![]u8 {
        return self.vtable.seal(self.ptr, allocator, random, plaintext, aad);
    }

    pub fn open(self: StateSealer, allocator: std.mem.Allocator, blob: []const u8, aad: []const u8) SealerError![]u8 {
        return self.vtable.open(self.ptr, allocator, blob, aad);
    }
};

pub const GrantSigner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const SignerError = error{
        OutOfMemory,
        SignFailed,
    };

    pub const GrantSpec = struct {
        ttl_s: u64,
        audience: []const u8,
        bound_to: ?[]const u8 = null,
    };

    pub const SealedGrant = struct {
        token: []u8,
    };

    pub const VTable = struct {
        seal: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, outcome: *const session.ChainOutcome, grant_spec: GrantSpec) SignerError![]u8,
    };

    pub fn seal(self: GrantSigner, allocator: std.mem.Allocator, outcome: *const session.ChainOutcome, grant_spec: GrantSpec) SignerError![]u8 {
        return self.vtable.seal(self.ptr, allocator, outcome, grant_spec);
    }
};

pub const GrantVerifier = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VerifiedFactor = struct {
        factor_id: []const u8,
        verified_at: i64,
        contributing: bool,
    };

    pub const VerifiedGrant = struct {
        subject_id: []u8,
        action_scope: []u8,
        policy_fingerprint: [32]u8,
        jti: []u8,
        iat: i64,
        exp: i64,
        aud: []u8,
        key_id: []u8,
        categories_mask: types.CategorySet,
        bound_to: ?[]u8 = null,
        factors: []VerifiedFactor = &.{},

        pub fn deinit(self: *VerifiedGrant, allocator: std.mem.Allocator) void {
            allocator.free(self.subject_id);
            allocator.free(self.action_scope);
            allocator.free(self.jti);
            allocator.free(self.aud);
            allocator.free(self.key_id);
            if (self.bound_to) |b| allocator.free(b);
            for (self.factors) |f| allocator.free(f.factor_id);
            allocator.free(self.factors);
            self.* = undefined;
        }
    };

    pub const VerifyError = error{
        OutOfMemory,
        InvalidGrant,
        InvalidSignature,
        ExpiredGrant,
        Expired,
        PolicyMismatch,
        AudienceMismatch,
        InvalidAudience,
        UnknownKeyId,
        ReplayedGrant,
    };

    pub const VTable = struct {
        open: *const fn (
            ctx: *anyopaque,
            allocator: std.mem.Allocator,
            token: []const u8,
            expected_audience: []const u8,
            expected_policies: []const [32]u8,
            now_unix_s: i64,
        ) VerifyError!VerifiedGrant,
    };

    pub fn open(
        self: GrantVerifier,
        allocator: std.mem.Allocator,
        token: []const u8,
        expected_audience: []const u8,
        expected_policies: []const [32]u8,
        now_unix_s: i64,
    ) VerifyError!VerifiedGrant {
        return self.vtable.open(self.ptr, allocator, token, expected_audience, expected_policies, now_unix_s);
    }
};

pub const ReplayGuard = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const GuardError = error{
        OutOfMemory,
        GuardUnavailable,
    };

    pub const Status = enum {
        fresh,
        replayed,
    };

    pub const VTable = struct {
        markUsed: *const fn (ctx: *anyopaque, jti: []const u8, exp: i64) GuardError!Status,
    };

    pub fn markUsed(self: ReplayGuard, jti: []const u8, exp: i64) GuardError!Status {
        return self.vtable.markUsed(self.ptr, jti, exp);
    }
};

pub const AuditSink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const AuditKind = enum {
        session_started,
        session_invalidated,
        session_expired,
        challenge_issued,
        challenge_rate_limited,
        proof_verified,
        proof_rejected,
        proof_pending,
        proof_rate_limited,
        set_rejected,
        binding_mismatch,
        protocol_violation,
        infra_error,
        conflict_retry,
        conflict_exhausted,
        outcome_taken,
        grant_sealed,
        outcomes_composed,
        recovery_used,
    };

    pub const AuditEvent = struct {
        kind: AuditKind,
        now_unix_s: i64,
        subject_id: ?[]const u8 = null,
        session_id: ?[]const u8 = null,
        factor_id: ?[]const u8 = null,
        source_key: ?[]const u8 = null,
        detail: u32 = 0,
    };

    pub const VTable = struct {
        emit: *const fn (ctx: *anyopaque, event: AuditEvent) void,
    };

    pub fn emit(self: AuditSink, event: AuditEvent) void {
        self.vtable.emit(self.ptr, event);
    }
};

pub const AdmissionPolicy = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const AdmissionError = error{
        OutOfMemory,
        AdmissionUnavailable,
    };

    pub const AdmissionPhase = enum {
        session_start,
        challenge_issue,
    };

    pub const AdmissionRequest = struct {
        phase: AdmissionPhase,
        action_scope: []const u8,
        subject_id: []const u8,
        factor_id: ?[]const u8 = null,
        factor_type: ?[]const u8 = null,
        source_key: ?[]const u8 = null,
        request_ctx: ?[]const u8 = null,
        now_unix_s: i64,
    };

    pub const AdmissionDecision = union(enum) {
        allow,
        defer_retry: struct {
            retry_after_s: u64,
        },
        deny,
    };

    pub const VTable = struct {
        evaluate: *const fn (ctx: *anyopaque, req: AdmissionRequest) AdmissionError!AdmissionDecision,
    };

    pub fn evaluate(self: AdmissionPolicy, req: AdmissionRequest) AdmissionError!AdmissionDecision {
        return self.vtable.evaluate(self.ptr, req);
    }
};

pub const EnrollmentVisibilityPolicy = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const SessionProgressView = struct {
        action_scope: []const u8,
        subject_id: []const u8,
        satisfied_categories: u8,
        satisfied_leaf_count: u8,
        is_bound: bool,
        now_unix_s: i64,
    };

    pub const VTable = struct {
        canRevealEnrolled: *const fn (ctx: *anyopaque, progress: SessionProgressView, request_ctx: ?[]const u8) bool,
    };

    pub fn canRevealEnrolled(self: EnrollmentVisibilityPolicy, progress: SessionProgressView, request_ctx: ?[]const u8) bool {
        return self.vtable.canRevealEnrolled(self.ptr, progress, request_ctx);
    }
};

pub const PolicyMigrationHook = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const ResolvedLegacyPolicy = struct {
        chain: *const policy.SecurityChain,
        assurance: types.AssurancePolicy,
        outcome_class: types.OutcomeClass,
        binding_mode: types.BindingMode,
        legacy_registry: ?*const registry_mod.FactorRegistry = null,
        sunset_unix_s: i64,
    };

    pub const VTable = struct {
        resolveLegacy: *const fn (
            ctx: *anyopaque,
            stored_fingerprint: [32]u8,
            action_scope: []const u8,
            effective_now: i64,
        ) ?ResolvedLegacyPolicy,
    };

    pub fn resolveLegacy(
        self: PolicyMigrationHook,
        stored_fingerprint: [32]u8,
        action_scope: []const u8,
        effective_now: i64,
    ) ?ResolvedLegacyPolicy {
        return self.vtable.resolveLegacy(self.ptr, stored_fingerprint, action_scope, effective_now);
    }
};
