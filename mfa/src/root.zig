const std = @import("std");

pub const primitives = @import("primitives.zig");
pub const errors = @import("errors.zig");
pub const types = @import("types.zig");
pub const ports = @import("ports.zig");
pub const registry = @import("registry.zig");
pub const policy = @import("policy.zig");
pub const fingerprint = @import("fingerprint.zig");
pub const session = @import("session.zig");
pub const engine = @import("engine.zig");
pub const verify = @import("verify.zig");
pub const helpers = @import("helpers.zig");
pub const testing = @import("testing.zig");

pub const wipe = primitives.wipe;
pub const ctEql32 = primitives.ctEql32;

pub const MfaError = errors.MfaError;
pub const InfraError = errors.InfraError;
pub const externalClass = errors.externalClass;

pub const max_policy_depth = types.max_policy_depth;
pub const max_policy_leaves = types.max_policy_leaves;
pub const CategorySet = types.CategorySet;
pub const Statefulness = types.Statefulness;
pub const BindingMode = types.BindingMode;
pub const OutcomeClass = types.OutcomeClass;
pub const EnrollmentMode = types.EnrollmentMode;
pub const EnrollmentVisibilityMode = types.EnrollmentVisibilityMode;
pub const FactorDescriptor = types.FactorDescriptor;
pub const SessionLimits = types.SessionLimits;
pub const AssurancePolicy = types.AssurancePolicy;

pub const RandomPort = ports.RandomPort;
pub const HashPort = ports.HashPort;
pub const FactorVerifier = ports.FactorVerifier;
pub const AttemptTracker = ports.AttemptTracker;
pub const FactorStateStore = ports.FactorStateStore;
pub const StateSealer = ports.StateSealer;
pub const GrantSigner = ports.GrantSigner;
pub const GrantVerifier = ports.GrantVerifier;
pub const ReplayGuard = ports.ReplayGuard;
pub const AuditSink = ports.AuditSink;
pub const AdmissionPolicy = ports.AdmissionPolicy;
pub const EnrollmentVisibilityPolicy = ports.EnrollmentVisibilityPolicy;
pub const PolicyMigrationHook = ports.PolicyMigrationHook;

pub const FactorRegistry = registry.FactorRegistry;
pub const ContextDependency = policy.ContextDependency;
pub const LeafNode = policy.LeafNode;
pub const ThresholdNode = policy.ThresholdNode;
pub const PolicyNode = policy.PolicyNode;
pub const SecurityChain = policy.SecurityChain;
pub const PolicyEnv = policy.PolicyEnv;
pub const validatePolicy = policy.validatePolicy;
pub const worstCaseStateSize = policy.worstCaseStateSize;
pub const requireNotWeaker = policy.requireNotWeaker;

pub const FingerprintOptions = fingerprint.FingerprintOptions;
pub const encodePolicy = fingerprint.encodePolicy;
pub const policyFingerprint = fingerprint.policyFingerprint;
pub const composedPolicyFingerprint = fingerprint.composedPolicyFingerprint;
pub const bindingHash = fingerprint.bindingHash;
pub const composedSessionId = fingerprint.composedSessionId;

pub const SessionStatus = session.SessionStatus;
pub const ChallengedData = session.ChallengedData;
pub const LeafPhase = session.LeafPhase;
pub const FactorOutput = session.FactorOutput;
pub const LeafSlot = session.LeafSlot;
pub const SessionState = session.SessionState;
pub const ChainOutcome = session.ChainOutcome;
pub const IntermediateOutcome = session.IntermediateOutcome;
pub const checkInvariants = session.checkInvariants;

pub const EngineEnv = engine.EngineEnv;
pub const CallMeta = engine.CallMeta;
pub const StartOptions = engine.StartOptions;
pub const StartOutcome = engine.StartOutcome;
pub const ChallengeOutcome = engine.ChallengeOutcome;
pub const EligibleFactorsResult = engine.EligibleFactorsResult;
pub const startChain = engine.startChain;
pub const requestChallenge = engine.requestChallenge;
pub const invalidateSession = engine.invalidateSession;
pub const eligibleFactors = engine.eligibleFactors;
pub const pendingFactors = engine.pendingFactors;

pub const SubmitOutcome = verify.SubmitOutcome;
pub const FactorProof = verify.FactorProof;
pub const SetOutcome = verify.SetOutcome;
pub const TakeOutcomeResult = verify.TakeOutcomeResult;
pub const submitProof = verify.submitProof;
pub const submitProofSet = verify.submitProofSet;
pub const takeOutcome = verify.takeOutcome;
pub const composeOutcomes = verify.composeOutcomes;
pub const sealGrant = verify.sealGrant;

pub const StatelessOnlyFactorStore = helpers.StatelessOnlyFactorStore;
pub const InMemoryAttemptTracker = helpers.InMemoryAttemptTracker;

comptime {
    std.testing.refAllDecls(@This());
}
