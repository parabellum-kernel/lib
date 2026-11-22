const std = @import("std");

pub const MfaError = error{
    SessionExpired,
    SessionCompleted,
    SessionInvalidated,
    SessionNotSatisfied,
    SessionBindingMismatch,
    OutcomeAlreadyTaken,
    ClockSkewDetected,
    InvalidSessionState,
    PolicyMismatch,
    PolicyUnsatisfiable,
    FactorNotFound,
    FactorNotInPolicy,
    FactorNotReady,
    FactorNotNeeded,
    FactorAlreadySatisfied,
    FactorNotEnrolled,
    BatchRequired,
    ChallengeRequired,
    ChallengeExpired,
    InvalidPolicy,
    DuplicateFactorId,
    LimitExceeded,
    WeakBinding,
    AdmissionDenied,
};

pub const InfraError = error{
    OutOfMemory,
    VerifierIoError,
    VerifierProtocolViolation,
    TrackerError,
    StateStoreError,
    SealError,
    GrantSignError,
    AdmissionError,
    EntropyError,
};

pub const Phase = enum {
    start,
    challenge,
    verify,
    outcome,
};

pub const ExternalErrorClass = enum {
    retry_later,
    rejected,
    rate_limited,
    internal,
};

pub fn externalClass(err: anyerror, phase: Phase) ExternalErrorClass {
    switch (err) {
        error.OutOfMemory,
        error.TrackerError,
        error.StateStoreError,
        error.SealError,
        error.GrantSignError,
        error.AdmissionError,
        error.EntropyError,
        => return .retry_later,

        error.VerifierIoError,
        error.VerifierProtocolViolation,
        => return switch (phase) {
            .verify => .rejected,
            .challenge => .retry_later,
            .start, .outcome => .internal,
        },

        error.SessionExpired,
        error.SessionCompleted,
        error.SessionInvalidated,
        error.SessionNotSatisfied,
        error.SessionBindingMismatch,
        error.OutcomeAlreadyTaken,
        error.ClockSkewDetected,
        error.InvalidSessionState,
        error.PolicyMismatch,
        error.PolicyUnsatisfiable,
        error.FactorNotFound,
        error.FactorNotInPolicy,
        error.FactorNotReady,
        error.FactorNotNeeded,
        error.FactorAlreadySatisfied,
        error.FactorNotEnrolled,
        error.BatchRequired,
        error.ChallengeRequired,
        error.ChallengeExpired,
        error.InvalidPolicy,
        error.DuplicateFactorId,
        error.LimitExceeded,
        error.WeakBinding,
        error.AdmissionDenied,
        => return .rejected,

        else => {
            if (phase == .verify) return .rejected;
            return .internal;
        },
    }
}

test "externalClass maps errors per MFA-13" {
    try std.testing.expectEqual(ExternalErrorClass.rejected, externalClass(error.VerifierIoError, .verify));
    try std.testing.expectEqual(ExternalErrorClass.retry_later, externalClass(error.VerifierIoError, .challenge));
    try std.testing.expectEqual(ExternalErrorClass.rejected, externalClass(error.VerifierProtocolViolation, .verify));
    try std.testing.expectEqual(ExternalErrorClass.retry_later, externalClass(error.VerifierProtocolViolation, .challenge));
    try std.testing.expectEqual(ExternalErrorClass.rejected, externalClass(error.LimitExceeded, .challenge));
    try std.testing.expectEqual(ExternalErrorClass.rejected, externalClass(error.AdmissionDenied, .start));
    try std.testing.expectEqual(ExternalErrorClass.retry_later, externalClass(error.EntropyError, .start));
    try std.testing.expectEqual(ExternalErrorClass.retry_later, externalClass(error.TrackerError, .verify));
}
