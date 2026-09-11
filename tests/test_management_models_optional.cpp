// Optional-field and enum-arm coverage for the generated management models.
//
// tests/test_management_models_generated.cpp round-trips every model through a wire object
// that carries EVERY property the spec declares. That proves no field is dropped, but it
// only ever walks the present side of an optional: `if (auto it = j.find("x"); it != j.end()
// && !it->is_null())` is entered on every run and never skipped, and the encode-side
// `if (value.x)` is likewise always true. The defect those branches guard against is the one
// this project already shipped once on the SCIM surface -- a PATCH that answered 200 and
// wrote nothing because only the present path had ever been exercised.
//
// So each case here asserts a property the full-wire suite cannot state:
//
//   * an optional the server did NOT send comes back absent, not as a default-constructed
//     value that a subsequent PUT would write over the server's data;
//   * an explicit JSON `null` is the same statement as an absent key;
//   * an optional collection the caller set to EMPTY is withheld, because the server
//     refuses an empty `tenant_scope` with 400 rather than reading it as "no narrowing";
//   * a free-form JSON member whose text does not parse is dropped rather than spliced
//     into the request as corrupt JSON;
//   * every enumerator spells to the wire value the server uses, and parses back.
//
// This file is hand-written and is NOT one of gen_management.py's outputs.

#include <optional>
#include <string>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"

// Internal, not installed -- the same reach the generated model suite makes.
#include "management_json.hpp"

namespace {

using namespace axiam::management;

// ---------------------------------------------------------------------------
// Enum wire spellings. A `switch` arm no test ever takes can ship the wrong string
// silently; `to_wire` is what goes out on an update, so a wrong arm is a wrong
// write. `Unknown` is asserted to spell as the empty string -- no server value is,
// so carrying an unrecognised value back is refused rather than guessed at.
// ---------------------------------------------------------------------------

AXIAM_TEST("management enum ActorType spells and parses every arm") {
    AXIAM_CHECK(to_wire(ActorType::User) == "User");
    AXIAM_CHECK(to_wire(ActorType::ServiceAccount) == "ServiceAccount");
    AXIAM_CHECK(to_wire(ActorType::System) == "System");

    AXIAM_CHECK(actor_type_from_wire("User") == ActorType::User);
    AXIAM_CHECK(actor_type_from_wire("ServiceAccount") == ActorType::ServiceAccount);
    AXIAM_CHECK(actor_type_from_wire("System") == ActorType::System);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(actor_type_from_wire("a-value-this-spec-copy-does-not-list") == ActorType::Unknown);
    AXIAM_CHECK(to_wire(ActorType::Unknown).empty());
}

AXIAM_TEST("management enum AttestationMode spells and parses every arm") {
    AXIAM_CHECK(to_wire(AttestationMode::None) == "none");
    AXIAM_CHECK(to_wire(AttestationMode::Indirect) == "indirect");
    AXIAM_CHECK(to_wire(AttestationMode::DirectRequired) == "direct_required");

    AXIAM_CHECK(attestation_mode_from_wire("none") == AttestationMode::None);
    AXIAM_CHECK(attestation_mode_from_wire("indirect") == AttestationMode::Indirect);
    AXIAM_CHECK(attestation_mode_from_wire("direct_required") == AttestationMode::DirectRequired);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(attestation_mode_from_wire("a-value-this-spec-copy-does-not-list") == AttestationMode::Unknown);
    AXIAM_CHECK(to_wire(AttestationMode::Unknown).empty());
}

AXIAM_TEST("management enum AuditOutcome spells and parses every arm") {
    AXIAM_CHECK(to_wire(AuditOutcome::Success) == "Success");
    AXIAM_CHECK(to_wire(AuditOutcome::Failure) == "Failure");
    AXIAM_CHECK(to_wire(AuditOutcome::Denied) == "Denied");

    AXIAM_CHECK(audit_outcome_from_wire("Success") == AuditOutcome::Success);
    AXIAM_CHECK(audit_outcome_from_wire("Failure") == AuditOutcome::Failure);
    AXIAM_CHECK(audit_outcome_from_wire("Denied") == AuditOutcome::Denied);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(audit_outcome_from_wire("a-value-this-spec-copy-does-not-list") == AuditOutcome::Unknown);
    AXIAM_CHECK(to_wire(AuditOutcome::Unknown).empty());
}

AXIAM_TEST("management enum AuthnRequestParamsMode spells and parses every arm") {
    AXIAM_CHECK(to_wire(AuthnRequestParamsMode::Ignore) == "ignore");
    AXIAM_CHECK(to_wire(AuthnRequestParamsMode::Honour) == "honour");

    AXIAM_CHECK(authn_request_params_mode_from_wire("ignore") == AuthnRequestParamsMode::Ignore);
    AXIAM_CHECK(authn_request_params_mode_from_wire("honour") == AuthnRequestParamsMode::Honour);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(authn_request_params_mode_from_wire("a-value-this-spec-copy-does-not-list") == AuthnRequestParamsMode::Unknown);
    AXIAM_CHECK(to_wire(AuthnRequestParamsMode::Unknown).empty());
}

AXIAM_TEST("management enum CertificateStatus spells and parses every arm") {
    AXIAM_CHECK(to_wire(CertificateStatus::Active) == "Active");
    AXIAM_CHECK(to_wire(CertificateStatus::Revoked) == "Revoked");
    AXIAM_CHECK(to_wire(CertificateStatus::Expired) == "Expired");

    AXIAM_CHECK(certificate_status_from_wire("Active") == CertificateStatus::Active);
    AXIAM_CHECK(certificate_status_from_wire("Revoked") == CertificateStatus::Revoked);
    AXIAM_CHECK(certificate_status_from_wire("Expired") == CertificateStatus::Expired);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(certificate_status_from_wire("a-value-this-spec-copy-does-not-list") == CertificateStatus::Unknown);
    AXIAM_CHECK(to_wire(CertificateStatus::Unknown).empty());
}

AXIAM_TEST("management enum CertificateType spells and parses every arm") {
    AXIAM_CHECK(to_wire(CertificateType::User) == "User");
    AXIAM_CHECK(to_wire(CertificateType::Service) == "Service");
    AXIAM_CHECK(to_wire(CertificateType::Device) == "Device");

    AXIAM_CHECK(certificate_type_from_wire("User") == CertificateType::User);
    AXIAM_CHECK(certificate_type_from_wire("Service") == CertificateType::Service);
    AXIAM_CHECK(certificate_type_from_wire("Device") == CertificateType::Device);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(certificate_type_from_wire("a-value-this-spec-copy-does-not-list") == CertificateType::Unknown);
    AXIAM_CHECK(to_wire(CertificateType::Unknown).empty());
}

AXIAM_TEST("management enum CertificationLevel spells and parses every arm") {
    AXIAM_CHECK(to_wire(CertificationLevel::L1) == "L1");
    AXIAM_CHECK(to_wire(CertificationLevel::L1Plus) == "L1Plus");
    AXIAM_CHECK(to_wire(CertificationLevel::L2) == "L2");
    AXIAM_CHECK(to_wire(CertificationLevel::L2Plus) == "L2Plus");
    AXIAM_CHECK(to_wire(CertificationLevel::L3) == "L3");
    AXIAM_CHECK(to_wire(CertificationLevel::L3Plus) == "L3Plus");

    AXIAM_CHECK(certification_level_from_wire("L1") == CertificationLevel::L1);
    AXIAM_CHECK(certification_level_from_wire("L1Plus") == CertificationLevel::L1Plus);
    AXIAM_CHECK(certification_level_from_wire("L2") == CertificationLevel::L2);
    AXIAM_CHECK(certification_level_from_wire("L2Plus") == CertificationLevel::L2Plus);
    AXIAM_CHECK(certification_level_from_wire("L3") == CertificationLevel::L3);
    AXIAM_CHECK(certification_level_from_wire("L3Plus") == CertificationLevel::L3Plus);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(certification_level_from_wire("a-value-this-spec-copy-does-not-list") == CertificationLevel::Unknown);
    AXIAM_CHECK(to_wire(CertificationLevel::Unknown).empty());
}

AXIAM_TEST("management enum ClientAuthMethod spells and parses every arm") {
    AXIAM_CHECK(to_wire(ClientAuthMethod::ClientSecretPost) == "client_secret_post");
    AXIAM_CHECK(to_wire(ClientAuthMethod::ClientSecretBasic) == "client_secret_basic");
    AXIAM_CHECK(to_wire(ClientAuthMethod::TlsClientAuth) == "tls_client_auth");
    AXIAM_CHECK(to_wire(ClientAuthMethod::SelfSignedTlsClientAuth) == "self_signed_tls_client_auth");
    AXIAM_CHECK(to_wire(ClientAuthMethod::PrivateKeyJwt) == "private_key_jwt");

    AXIAM_CHECK(client_auth_method_from_wire("client_secret_post") == ClientAuthMethod::ClientSecretPost);
    AXIAM_CHECK(client_auth_method_from_wire("client_secret_basic") == ClientAuthMethod::ClientSecretBasic);
    AXIAM_CHECK(client_auth_method_from_wire("tls_client_auth") == ClientAuthMethod::TlsClientAuth);
    AXIAM_CHECK(client_auth_method_from_wire("self_signed_tls_client_auth") == ClientAuthMethod::SelfSignedTlsClientAuth);
    AXIAM_CHECK(client_auth_method_from_wire("private_key_jwt") == ClientAuthMethod::PrivateKeyJwt);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(client_auth_method_from_wire("a-value-this-spec-copy-does-not-list") == ClientAuthMethod::Unknown);
    AXIAM_CHECK(to_wire(ClientAuthMethod::Unknown).empty());
}

AXIAM_TEST("management enum ClientProfile spells and parses every arm") {
    AXIAM_CHECK(to_wire(ClientProfile::Standard) == "standard");
    AXIAM_CHECK(to_wire(ClientProfile::Fapi2) == "fapi2");

    AXIAM_CHECK(client_profile_from_wire("standard") == ClientProfile::Standard);
    AXIAM_CHECK(client_profile_from_wire("fapi2") == ClientProfile::Fapi2);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(client_profile_from_wire("a-value-this-spec-copy-does-not-list") == ClientProfile::Unknown);
    AXIAM_CHECK(to_wire(ClientProfile::Unknown).empty());
}

AXIAM_TEST("management enum FailurePolicy spells and parses every arm") {
    AXIAM_CHECK(to_wire(FailurePolicy::FailClosed) == "fail_closed");
    AXIAM_CHECK(to_wire(FailurePolicy::FailOpen) == "fail_open");

    AXIAM_CHECK(failure_policy_from_wire("fail_closed") == FailurePolicy::FailClosed);
    AXIAM_CHECK(failure_policy_from_wire("fail_open") == FailurePolicy::FailOpen);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(failure_policy_from_wire("a-value-this-spec-copy-does-not-list") == FailurePolicy::Unknown);
    AXIAM_CHECK(to_wire(FailurePolicy::Unknown).empty());
}

AXIAM_TEST("management enum KeyAlgorithm spells and parses every arm") {
    AXIAM_CHECK(to_wire(KeyAlgorithm::Rsa4096) == "Rsa4096");
    AXIAM_CHECK(to_wire(KeyAlgorithm::Ed25519) == "Ed25519");

    AXIAM_CHECK(key_algorithm_from_wire("Rsa4096") == KeyAlgorithm::Rsa4096);
    AXIAM_CHECK(key_algorithm_from_wire("Ed25519") == KeyAlgorithm::Ed25519);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(key_algorithm_from_wire("a-value-this-spec-copy-does-not-list") == KeyAlgorithm::Unknown);
    AXIAM_CHECK(to_wire(KeyAlgorithm::Unknown).empty());
}

AXIAM_TEST("management enum MfaMethodType spells and parses every arm") {
    AXIAM_CHECK(to_wire(MfaMethodType::Totp) == "Totp");
    AXIAM_CHECK(to_wire(MfaMethodType::Passkey) == "Passkey");
    AXIAM_CHECK(to_wire(MfaMethodType::SecurityKey) == "SecurityKey");

    AXIAM_CHECK(mfa_method_type_from_wire("Totp") == MfaMethodType::Totp);
    AXIAM_CHECK(mfa_method_type_from_wire("Passkey") == MfaMethodType::Passkey);
    AXIAM_CHECK(mfa_method_type_from_wire("SecurityKey") == MfaMethodType::SecurityKey);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(mfa_method_type_from_wire("a-value-this-spec-copy-does-not-list") == MfaMethodType::Unknown);
    AXIAM_CHECK(to_wire(MfaMethodType::Unknown).empty());
}

AXIAM_TEST("management enum NotificationEventType spells and parses every arm") {
    AXIAM_CHECK(to_wire(NotificationEventType::LoginFailure) == "login_failure");
    AXIAM_CHECK(to_wire(NotificationEventType::AccountLocked) == "account_locked");
    AXIAM_CHECK(to_wire(NotificationEventType::MfaEnrollmentChanged) == "mfa_enrollment_changed");
    AXIAM_CHECK(to_wire(NotificationEventType::PasswordChanged) == "password_changed");
    AXIAM_CHECK(to_wire(NotificationEventType::PasswordResetRequested) == "password_reset_requested");
    AXIAM_CHECK(to_wire(NotificationEventType::RoleAssigned) == "role_assigned");
    AXIAM_CHECK(to_wire(NotificationEventType::RoleUnassigned) == "role_unassigned");
    AXIAM_CHECK(to_wire(NotificationEventType::PermissionGranted) == "permission_granted");
    AXIAM_CHECK(to_wire(NotificationEventType::PermissionRevoked) == "permission_revoked");
    AXIAM_CHECK(to_wire(NotificationEventType::CertificateIssued) == "certificate_issued");
    AXIAM_CHECK(to_wire(NotificationEventType::CertificateRevoked) == "certificate_revoked");
    AXIAM_CHECK(to_wire(NotificationEventType::CaCertificateRevoked) == "ca_certificate_revoked");
    AXIAM_CHECK(to_wire(NotificationEventType::UserCreated) == "user_created");
    AXIAM_CHECK(to_wire(NotificationEventType::UserDeleted) == "user_deleted");
    AXIAM_CHECK(to_wire(NotificationEventType::UserUpdated) == "user_updated");
    AXIAM_CHECK(to_wire(NotificationEventType::ServiceAccountCreated) == "service_account_created");
    AXIAM_CHECK(to_wire(NotificationEventType::ServiceAccountDeleted) == "service_account_deleted");

    AXIAM_CHECK(notification_event_type_from_wire("login_failure") == NotificationEventType::LoginFailure);
    AXIAM_CHECK(notification_event_type_from_wire("account_locked") == NotificationEventType::AccountLocked);
    AXIAM_CHECK(notification_event_type_from_wire("mfa_enrollment_changed") == NotificationEventType::MfaEnrollmentChanged);
    AXIAM_CHECK(notification_event_type_from_wire("password_changed") == NotificationEventType::PasswordChanged);
    AXIAM_CHECK(notification_event_type_from_wire("password_reset_requested") == NotificationEventType::PasswordResetRequested);
    AXIAM_CHECK(notification_event_type_from_wire("role_assigned") == NotificationEventType::RoleAssigned);
    AXIAM_CHECK(notification_event_type_from_wire("role_unassigned") == NotificationEventType::RoleUnassigned);
    AXIAM_CHECK(notification_event_type_from_wire("permission_granted") == NotificationEventType::PermissionGranted);
    AXIAM_CHECK(notification_event_type_from_wire("permission_revoked") == NotificationEventType::PermissionRevoked);
    AXIAM_CHECK(notification_event_type_from_wire("certificate_issued") == NotificationEventType::CertificateIssued);
    AXIAM_CHECK(notification_event_type_from_wire("certificate_revoked") == NotificationEventType::CertificateRevoked);
    AXIAM_CHECK(notification_event_type_from_wire("ca_certificate_revoked") == NotificationEventType::CaCertificateRevoked);
    AXIAM_CHECK(notification_event_type_from_wire("user_created") == NotificationEventType::UserCreated);
    AXIAM_CHECK(notification_event_type_from_wire("user_deleted") == NotificationEventType::UserDeleted);
    AXIAM_CHECK(notification_event_type_from_wire("user_updated") == NotificationEventType::UserUpdated);
    AXIAM_CHECK(notification_event_type_from_wire("service_account_created") == NotificationEventType::ServiceAccountCreated);
    AXIAM_CHECK(notification_event_type_from_wire("service_account_deleted") == NotificationEventType::ServiceAccountDeleted);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(notification_event_type_from_wire("a-value-this-spec-copy-does-not-list") == NotificationEventType::Unknown);
    AXIAM_CHECK(to_wire(NotificationEventType::Unknown).empty());
}

AXIAM_TEST("management enum PermissionEffect spells and parses every arm") {
    AXIAM_CHECK(to_wire(PermissionEffect::Allow) == "allow");
    AXIAM_CHECK(to_wire(PermissionEffect::Deny) == "deny");

    AXIAM_CHECK(permission_effect_from_wire("allow") == PermissionEffect::Allow);
    AXIAM_CHECK(permission_effect_from_wire("deny") == PermissionEffect::Deny);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(permission_effect_from_wire("a-value-this-spec-copy-does-not-list") == PermissionEffect::Unknown);
    AXIAM_CHECK(to_wire(PermissionEffect::Unknown).empty());
}

AXIAM_TEST("management enum PgpKeyAlgorithm spells and parses every arm") {
    AXIAM_CHECK(to_wire(PgpKeyAlgorithm::Rsa4096) == "Rsa4096");
    AXIAM_CHECK(to_wire(PgpKeyAlgorithm::Ed25519) == "Ed25519");

    AXIAM_CHECK(pgp_key_algorithm_from_wire("Rsa4096") == PgpKeyAlgorithm::Rsa4096);
    AXIAM_CHECK(pgp_key_algorithm_from_wire("Ed25519") == PgpKeyAlgorithm::Ed25519);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(pgp_key_algorithm_from_wire("a-value-this-spec-copy-does-not-list") == PgpKeyAlgorithm::Unknown);
    AXIAM_CHECK(to_wire(PgpKeyAlgorithm::Unknown).empty());
}

AXIAM_TEST("management enum PgpKeyPurpose spells and parses every arm") {
    AXIAM_CHECK(to_wire(PgpKeyPurpose::AuditSigning) == "AuditSigning");
    AXIAM_CHECK(to_wire(PgpKeyPurpose::Export_) == "Export");

    AXIAM_CHECK(pgp_key_purpose_from_wire("AuditSigning") == PgpKeyPurpose::AuditSigning);
    AXIAM_CHECK(pgp_key_purpose_from_wire("Export") == PgpKeyPurpose::Export_);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(pgp_key_purpose_from_wire("a-value-this-spec-copy-does-not-list") == PgpKeyPurpose::Unknown);
    AXIAM_CHECK(to_wire(PgpKeyPurpose::Unknown).empty());
}

AXIAM_TEST("management enum PgpKeyStatus spells and parses every arm") {
    AXIAM_CHECK(to_wire(PgpKeyStatus::Active) == "Active");
    AXIAM_CHECK(to_wire(PgpKeyStatus::Revoked) == "Revoked");

    AXIAM_CHECK(pgp_key_status_from_wire("Active") == PgpKeyStatus::Active);
    AXIAM_CHECK(pgp_key_status_from_wire("Revoked") == PgpKeyStatus::Revoked);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(pgp_key_status_from_wire("a-value-this-spec-copy-does-not-list") == PgpKeyStatus::Unknown);
    AXIAM_CHECK(to_wire(PgpKeyStatus::Unknown).empty());
}

AXIAM_TEST("management enum ReactorMode spells and parses every arm") {
    AXIAM_CHECK(to_wire(ReactorMode::Intercept) == "intercept");
    AXIAM_CHECK(to_wire(ReactorMode::Listen) == "listen");

    AXIAM_CHECK(reactor_mode_from_wire("intercept") == ReactorMode::Intercept);
    AXIAM_CHECK(reactor_mode_from_wire("listen") == ReactorMode::Listen);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(reactor_mode_from_wire("a-value-this-spec-copy-does-not-list") == ReactorMode::Unknown);
    AXIAM_CHECK(to_wire(ReactorMode::Unknown).empty());
}

AXIAM_TEST("management enum ScimTokenStatus spells and parses every arm") {
    AXIAM_CHECK(to_wire(ScimTokenStatus::Active) == "active");
    AXIAM_CHECK(to_wire(ScimTokenStatus::Expired) == "expired");
    AXIAM_CHECK(to_wire(ScimTokenStatus::Revoked) == "revoked");

    AXIAM_CHECK(scim_token_status_from_wire("active") == ScimTokenStatus::Active);
    AXIAM_CHECK(scim_token_status_from_wire("expired") == ScimTokenStatus::Expired);
    AXIAM_CHECK(scim_token_status_from_wire("revoked") == ScimTokenStatus::Revoked);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(scim_token_status_from_wire("a-value-this-spec-copy-does-not-list") == ScimTokenStatus::Unknown);
    AXIAM_CHECK(to_wire(ScimTokenStatus::Unknown).empty());
}

AXIAM_TEST("management enum SettingsScope spells and parses every arm") {
    AXIAM_CHECK(to_wire(SettingsScope::Org) == "Org");
    AXIAM_CHECK(to_wire(SettingsScope::Tenant) == "Tenant");

    AXIAM_CHECK(settings_scope_from_wire("Org") == SettingsScope::Org);
    AXIAM_CHECK(settings_scope_from_wire("Tenant") == SettingsScope::Tenant);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(settings_scope_from_wire("a-value-this-spec-copy-does-not-list") == SettingsScope::Unknown);
    AXIAM_CHECK(to_wire(SettingsScope::Unknown).empty());
}

AXIAM_TEST("management enum TenantKind spells and parses every arm") {
    AXIAM_CHECK(to_wire(TenantKind::Standard) == "standard");
    AXIAM_CHECK(to_wire(TenantKind::Organization) == "organization");

    AXIAM_CHECK(tenant_kind_from_wire("standard") == TenantKind::Standard);
    AXIAM_CHECK(tenant_kind_from_wire("organization") == TenantKind::Organization);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(tenant_kind_from_wire("a-value-this-spec-copy-does-not-list") == TenantKind::Unknown);
    AXIAM_CHECK(to_wire(TenantKind::Unknown).empty());
}

AXIAM_TEST("management enum TenantStatus spells and parses every arm") {
    AXIAM_CHECK(to_wire(TenantStatus::Active) == "Active");
    AXIAM_CHECK(to_wire(TenantStatus::Suspended) == "Suspended");

    AXIAM_CHECK(tenant_status_from_wire("Active") == TenantStatus::Active);
    AXIAM_CHECK(tenant_status_from_wire("Suspended") == TenantStatus::Suspended);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(tenant_status_from_wire("a-value-this-spec-copy-does-not-list") == TenantStatus::Unknown);
    AXIAM_CHECK(to_wire(TenantStatus::Unknown).empty());
}

AXIAM_TEST("management enum UnknownAaguidAction spells and parses every arm") {
    AXIAM_CHECK(to_wire(UnknownAaguidAction::Allow) == "allow");
    AXIAM_CHECK(to_wire(UnknownAaguidAction::Deny) == "deny");

    AXIAM_CHECK(unknown_aaguid_action_from_wire("allow") == UnknownAaguidAction::Allow);
    AXIAM_CHECK(unknown_aaguid_action_from_wire("deny") == UnknownAaguidAction::Deny);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(unknown_aaguid_action_from_wire("a-value-this-spec-copy-does-not-list") == UnknownAaguidAction::Unknown);
    AXIAM_CHECK(to_wire(UnknownAaguidAction::Unknown).empty());
}

AXIAM_TEST("management enum UserStatus spells and parses every arm") {
    AXIAM_CHECK(to_wire(UserStatus::Active) == "Active");
    AXIAM_CHECK(to_wire(UserStatus::Inactive) == "Inactive");
    AXIAM_CHECK(to_wire(UserStatus::Locked) == "Locked");
    AXIAM_CHECK(to_wire(UserStatus::PendingVerification) == "PendingVerification");
    AXIAM_CHECK(to_wire(UserStatus::Anonymized) == "Anonymized");
    AXIAM_CHECK(to_wire(UserStatus::Deleted) == "Deleted");

    AXIAM_CHECK(user_status_from_wire("Active") == UserStatus::Active);
    AXIAM_CHECK(user_status_from_wire("Inactive") == UserStatus::Inactive);
    AXIAM_CHECK(user_status_from_wire("Locked") == UserStatus::Locked);
    AXIAM_CHECK(user_status_from_wire("PendingVerification") == UserStatus::PendingVerification);
    AXIAM_CHECK(user_status_from_wire("Anonymized") == UserStatus::Anonymized);
    AXIAM_CHECK(user_status_from_wire("Deleted") == UserStatus::Deleted);

    // §27.11 rule 1: a value this SDK's copy of the spec does not list decodes to
    // Unknown rather than throwing, and is never folded into a known enumerator.
    AXIAM_CHECK(user_status_from_wire("a-value-this-spec-copy-does-not-list") == UserStatus::Unknown);
    AXIAM_CHECK(to_wire(UserStatus::Unknown).empty());
}

// ---------------------------------------------------------------------------
// Optional fields: absent stays absent, and an explicit null reads as absent.
// ---------------------------------------------------------------------------

AXIAM_TEST("management model ApiProviderConfig withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<ApiProviderConfig>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["api_url"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ApiProviderConfig>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model AssignRoleToGroupRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"group_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<AssignRoleToGroupRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<AssignRoleToGroupRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model AssignRoleToServiceAccountRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"service_account_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<AssignRoleToServiceAccountRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<AssignRoleToServiceAccountRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model AssignRoleToUserRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<AssignRoleToUserRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<AssignRoleToUserRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model AuditLogEntry withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"action": "example", "actor_id": "11111111-1111-4111-8111-111111111111", "actor_type": "User", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "outcome": "Success", "tenant_id": "11111111-1111-4111-8111-111111111111", "timestamp": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<AuditLogEntry>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["ip_address"] = nullptr;
    nulls["resource_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<AuditLogEntry>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CaCertificate withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "organization_id": "11111111-1111-4111-8111-111111111111", "public_cert_pem": "example", "status": "Active", "subject": "example"})json");

    const nlohmann::json encoded = minimal.get<CaCertificate>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["chain_pem"] = nullptr;
    nulls["key_custody"] = nullptr;
    nulls["key_locator"] = nullptr;
    nulls["mtls_trust_anchor"] = nullptr;
    nulls["parent_ca_id"] = nullptr;
    nulls["tenant_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CaCertificate>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model Certificate withholds optionals it was not given") {
    // No optional property is set.
    const auto minimal = nlohmann::json::parse(
        R"json({"cert_type": "User", "created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "metadata": {}, "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "public_cert_pem": "example", "status": "Active", "subject": "example", "tenant_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<Certificate>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["bound_service_account_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<Certificate>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ComplianceReportEntry withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"compliant": true, "credential_id": "11111111-1111-4111-8111-111111111111", "name": "example", "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<ComplianceReportEntry>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["aaguid"] = nullptr;
    nulls["authenticator_name"] = nullptr;
    nulls["reason"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ComplianceReportEntry>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateCaCertificateRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"key_algorithm": "Rsa4096", "subject": "example", "validity_days": 1})json");

    const nlohmann::json encoded = minimal.get<CreateCaCertificateRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["intermediate_subject"] = nullptr;
    nulls["intermediate_validity_days"] = nullptr;
    nulls["issue_from_root"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateCaCertificateRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateCertificateRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"cert_type": "User", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "subject": "example", "validity_days": 1})json");

    const nlohmann::json encoded = minimal.get<CreateCertificateRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateCertificateRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateFederationConfigRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"client_id": "example", "client_secret": "example", "protocol": "example", "provider": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateFederationConfigRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["allow_tenant_inheritance"] = nullptr;
    nulls["allowed_algorithms"] = nullptr;
    nulls["allowed_issuer_tenants"] = nullptr;
    nulls["apple_key_id"] = nullptr;
    nulls["apple_team_id"] = nullptr;
    nulls["attribute_map"] = nullptr;
    nulls["authorization_endpoint"] = nullptr;
    nulls["button_icon"] = nullptr;
    nulls["idp_signing_cert_pem"] = nullptr;
    nulls["metadata_url"] = nullptr;
    nulls["provider_kind"] = nullptr;
    nulls["provider_slug"] = nullptr;
    nulls["require_pkce"] = nullptr;
    nulls["scopes"] = nullptr;
    nulls["token_endpoint"] = nullptr;
    nulls["token_exchange"] = nullptr;
    nulls["userinfo_endpoint"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateFederationConfigRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateGroupRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"description": "example", "name": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateGroupRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateGroupRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateOAuth2ClientRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"grant_types": ["example"], "name": "example", "redirect_uris": ["example"], "scopes": ["example"]})json");

    const nlohmann::json encoded = minimal.get<CreateOAuth2ClientRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["authn_request_params"] = nullptr;
    nulls["backchannel_logout_uri"] = nullptr;
    nulls["browser_sso"] = nullptr;
    nulls["dpop_bound_access_tokens"] = nullptr;
    nulls["dpop_require_nonce"] = nullptr;
    nulls["jwks"] = nullptr;
    nulls["jwks_uri"] = nullptr;
    nulls["post_logout_redirect_uris"] = nullptr;
    nulls["profile"] = nullptr;
    nulls["require_par"] = nullptr;
    nulls["self_signed_tls_client_auth_thumbprints"] = nullptr;
    nulls["tls_client_auth_san_dns"] = nullptr;
    nulls["tls_client_auth_san_uri"] = nullptr;
    nulls["tls_client_auth_subject_dn"] = nullptr;
    nulls["tls_client_certificate_bound_access_tokens"] = nullptr;
    nulls["token_endpoint_auth_method"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateOAuth2ClientRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateReactorRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"events": ["example"], "mode": "intercept", "name": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateReactorRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["enabled"] = nullptr;
    nulls["failure_policy"] = nullptr;
    nulls["priority"] = nullptr;
    nulls["timeout_ms"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateReactorRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateResourceRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"name": "example", "resource_type": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateResourceRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    nulls["parent_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateResourceRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateScimTokenRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"name": "example", "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<CreateScimTokenRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["expires_in_days"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateScimTokenRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateScimTokenResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "created_by": "11111111-1111-4111-8111-111111111111", "expires_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "provisioning_token": "example", "status": "active", "tenant_id": "11111111-1111-4111-8111-111111111111", "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<CreateScimTokenResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["last_used_at"] = nullptr;
    nulls["revoked_at"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateScimTokenResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateServiceAccountRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"name": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateServiceAccountRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateServiceAccountRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateTenantRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"name": "example", "slug": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateTenantRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateTenantRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateUserRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"email": "example", "password": "example", "username": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateUserRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    nulls["opaque"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateUserRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model CreateWebhookRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"events": ["example"], "secret": "example", "url": "example"})json");

    const nlohmann::json encoded = minimal.get<CreateWebhookRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["retry_policy"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<CreateWebhookRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model EmailConfig withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "enabled": true, "from_email": "example", "from_name": "example", "id": "11111111-1111-4111-8111-111111111111", "provider": {"host": "example", "kind": "smtp", "port": 1, "starttls": true, "username": "example"}, "scope": "Org", "scope_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<EmailConfig>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["reply_to"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<EmailConfig>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model EmailConfigOverride withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<EmailConfigOverride>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["enabled"] = nullptr;
    nulls["from_email"] = nullptr;
    nulls["from_name"] = nullptr;
    nulls["provider"] = nullptr;
    nulls["reply_to"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<EmailConfigOverride>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model EmailTestResult withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"provider": "example", "to": "example"})json");

    const nlohmann::json encoded = minimal.get<EmailTestResult>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["message_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<EmailTestResult>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model FederationConfigResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"allow_tenant_inheritance": true, "allowed_algorithms": ["example"], "allowed_issuer_tenants": ["example"], "attribute_map": {}, "client_id": "example", "created_at": "2026-08-26T00:00:00Z", "effective_scopes": ["example"], "enabled": true, "has_bundled_mark": true, "id": "11111111-1111-4111-8111-111111111111", "mints_client_secret": true, "pkce_required": true, "protocol": "example", "provider": "example", "provider_kind": "example", "scopes": ["example"], "tenant_id": "11111111-1111-4111-8111-111111111111", "token_exchange": {"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"}, "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<FederationConfigResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["apple_key_id"] = nullptr;
    nulls["apple_team_id"] = nullptr;
    nulls["authorization_endpoint"] = nullptr;
    nulls["button_icon"] = nullptr;
    nulls["metadata_url"] = nullptr;
    nulls["provider_slug"] = nullptr;
    nulls["token_endpoint"] = nullptr;
    nulls["userinfo_endpoint"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<FederationConfigResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model FederationLinkResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "external_subject": "example", "federation_config_id": "11111111-1111-4111-8111-111111111111", "id": "11111111-1111-4111-8111-111111111111", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<FederationLinkResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["external_email"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<FederationLinkResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model GeneratedCaCertificate withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "organization_id": "11111111-1111-4111-8111-111111111111", "public_cert_pem": "example", "status": "Active", "subject": "example"})json");

    const nlohmann::json encoded = minimal.get<GeneratedCaCertificate>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["chain_pem"] = nullptr;
    nulls["key_custody"] = nullptr;
    nulls["key_locator"] = nullptr;
    nulls["mtls_trust_anchor"] = nullptr;
    nulls["parent_ca_id"] = nullptr;
    nulls["private_key_pem"] = nullptr;
    nulls["tenant_id"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<GeneratedCaCertificate>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model GeneratedCertificate withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"cert_type": "User", "created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "metadata": {}, "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "private_key_pem": "example", "public_cert_pem": "example", "status": "Active", "subject": "example", "tenant_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<GeneratedCertificate>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["chain_pem"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<GeneratedCertificate>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model GeneratedPgpKey withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"algorithm": "Rsa4096", "created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "public_key_armored": "example", "purpose": "AuditSigning", "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<GeneratedPgpKey>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["private_key_armored"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<GeneratedPgpKey>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model GrantPermissionRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"permission_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<GrantPermissionRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["effect"] = nullptr;
    nulls["scope_ids"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<GrantPermissionRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ImportCaCertificateRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"public_cert_pem": "example"})json");

    const nlohmann::json encoded = minimal.get<ImportCaCertificateRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["private_key_pem"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ImportCaCertificateRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model MdsStatusResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"entry_count": 1, "stale": true})json");

    const nlohmann::json encoded = minimal.get<MdsStatusResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["last_refreshed_at"] = nullptr;
    nulls["next_update"] = nullptr;
    nulls["no"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<MdsStatusResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model MfaMethodResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "example", "method_id": "example", "method_type": "Totp", "name": "example"})json");

    const nlohmann::json encoded = minimal.get<MfaMethodResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["last_used_at"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<MfaMethodResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model MigrateCustodyResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"ca_certificate_id": "11111111-1111-4111-8111-111111111111", "key_custody": "example", "previous_custody": "example"})json");

    const nlohmann::json encoded = minimal.get<MigrateCustodyResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["key_locator"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<MigrateCustodyResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model MtlsTrustAnchorResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"ca_certificate_id": "11111111-1111-4111-8111-111111111111", "message": "example", "mtls_trust_anchor": true, "restart_required": true})json");

    const nlohmann::json encoded = minimal.get<MtlsTrustAnchorResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["trusted_anchors"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<MtlsTrustAnchorResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model OAuth2ClientResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"authn_request_params": "ignore", "browser_sso": true, "client_id": "example", "created_at": "2026-08-26T00:00:00Z", "dpop_bound_access_tokens": true, "dpop_require_nonce": true, "grant_types": ["example"], "id": "11111111-1111-4111-8111-111111111111", "name": "example", "profile": "standard", "redirect_uris": ["example"], "require_par": true, "scopes": ["example"], "self_signed_tls_client_auth_thumbprints": ["example"], "tenant_id": "11111111-1111-4111-8111-111111111111", "tls_client_certificate_bound_access_tokens": true, "token_endpoint_auth_method": "client_secret_post", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<OAuth2ClientResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["jwks"] = nullptr;
    nulls["jwks_uri"] = nullptr;
    nulls["tls_client_auth_san_dns"] = nullptr;
    nulls["tls_client_auth_san_uri"] = nullptr;
    nulls["tls_client_auth_subject_dn"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<OAuth2ClientResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model OidcPolicy withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"sensitive_scopes_enabled": true})json");

    const nlohmann::json encoded = minimal.get<OidcPolicy>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["default_locale"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<OidcPolicy>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model PolicyResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"block_revoked_status": true, "effective_unknown_aaguid": "allow", "mode": "none", "require_fido_certified": true})json");

    const nlohmann::json encoded = minimal.get<PolicyResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["allowed_aaguids"] = nullptr;
    nulls["blocked_aaguids"] = nullptr;
    nulls["min_certification"] = nullptr;
    nulls["unknown_aaguid"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<PolicyResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ReactorResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "description": "example", "enabled": true, "events": ["example"], "failure_policy": "fail_closed", "id": "11111111-1111-4111-8111-111111111111", "mode": "intercept", "name": "example", "priority": 1, "recent_timeout_count": 1, "recent_veto_count": 1, "tenant_id": "11111111-1111-4111-8111-111111111111", "timeout_ms": 1, "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<ReactorResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["last_seen_at"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ReactorResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model Resource withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "resource_type": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<Resource>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["parent_id"] = nullptr;
    nulls["uma_registered_by"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<Resource>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model RoleAssignment withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"role": {"created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "is_global": true, "name": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}})json");

    const nlohmann::json encoded = minimal.get<RoleAssignment>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<RoleAssignment>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model RoleGroupAssignment withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"group": {"created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}})json");

    const nlohmann::json encoded = minimal.get<RoleGroupAssignment>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<RoleGroupAssignment>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model RoleServiceAccountAssignment withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"service_account": {"client_id": "example", "created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}})json");

    const nlohmann::json encoded = minimal.get<RoleServiceAccountAssignment>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<RoleServiceAccountAssignment>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model RoleUserAssignment withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"user": {"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "locked_until": "2026-08-26T00:00:00Z", "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"}})json");

    const nlohmann::json encoded = minimal.get<RoleUserAssignment>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["resource_id"] = nullptr;
    nulls["tenant_scope"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<RoleUserAssignment>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ScimTokenResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "created_by": "11111111-1111-4111-8111-111111111111", "expires_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "status": "active", "tenant_id": "11111111-1111-4111-8111-111111111111", "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const nlohmann::json encoded = minimal.get<ScimTokenResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["last_used_at"] = nullptr;
    nulls["revoked_at"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ScimTokenResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ServiceAccountCreatedResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"client_id": "example", "client_secret": "example", "created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<ServiceAccountCreatedResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ServiceAccountCreatedResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model ServiceAccountResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"client_id": "example", "created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<ServiceAccountResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<ServiceAccountResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model SetOrgEmailConfig withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"enabled": true, "from_email": "example", "from_name": "example", "provider": {"host": "example", "kind": "smtp", "port": 1, "starttls": true, "username": "example"}})json");

    const nlohmann::json encoded = minimal.get<SetOrgEmailConfig>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["reply_to"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<SetOrgEmailConfig>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model SetOrgSettings withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"access_token_lifetime_secs": 1, "admin_notifications_enabled": true, "default_cert_validity_days": 1, "email_verification_grace_period_hours": 1, "email_verification_required": true, "hibp_check_enabled": true, "lockout_backoff_multiplier": 1.5, "lockout_duration_secs": 1, "max_cert_validity_days": 1, "max_failed_login_attempts": 1, "max_lockout_duration_secs": 1, "mfa_challenge_lifetime_secs": 1, "mfa_enforced": true, "min_length": 1, "password_history_count": 1, "refresh_token_lifetime_secs": 1, "require_digits": true, "require_lowercase": true, "require_symbols": true, "require_uppercase": true})json");

    const nlohmann::json encoded = minimal.get<SetOrgSettings>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["default_locale"] = nullptr;
    nulls["deletion_grace_period_days"] = nullptr;
    nulls["opaque_ksf"] = nullptr;
    nulls["opaque_mode"] = nullptr;
    nulls["opaque_suite"] = nullptr;
    nulls["sensitive_scopes_enabled"] = nullptr;
    nulls["webauthn_user_verification"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<SetOrgSettings>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model Tenant withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "organization_id": "11111111-1111-4111-8111-111111111111", "slug": "example", "status": "Active", "updated_at": "2026-08-26T00:00:00Z"})json");

    const nlohmann::json encoded = minimal.get<Tenant>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["kind"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<Tenant>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model TenantSettingsOverride withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<TenantSettingsOverride>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["access_token_lifetime_secs"] = nullptr;
    nulls["admin_notifications_enabled"] = nullptr;
    nulls["default_cert_validity_days"] = nullptr;
    nulls["default_locale"] = nullptr;
    nulls["deletion_grace_period_days"] = nullptr;
    nulls["email_verification_grace_period_hours"] = nullptr;
    nulls["email_verification_required"] = nullptr;
    nulls["hibp_check_enabled"] = nullptr;
    nulls["lockout_backoff_multiplier"] = nullptr;
    nulls["lockout_duration_secs"] = nullptr;
    nulls["max_cert_validity_days"] = nullptr;
    nulls["max_failed_login_attempts"] = nullptr;
    nulls["max_lockout_duration_secs"] = nullptr;
    nulls["mfa_challenge_lifetime_secs"] = nullptr;
    nulls["mfa_enforced"] = nullptr;
    nulls["min_length"] = nullptr;
    nulls["opaque_ksf"] = nullptr;
    nulls["opaque_mode"] = nullptr;
    nulls["opaque_suite"] = nullptr;
    nulls["password_history_count"] = nullptr;
    nulls["refresh_token_lifetime_secs"] = nullptr;
    nulls["require_digits"] = nullptr;
    nulls["require_lowercase"] = nullptr;
    nulls["require_symbols"] = nullptr;
    nulls["require_uppercase"] = nullptr;
    nulls["sensitive_scopes_enabled"] = nullptr;
    nulls["webauthn_user_verification"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<TenantSettingsOverride>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model TokenExchangeTrustRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<TokenExchangeTrustRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["accepted_audiences"] = nullptr;
    nulls["enabled"] = nullptr;
    nulls["max_lifetime_secs"] = nullptr;
    nulls["max_token_age_secs"] = nullptr;
    nulls["scope_map"] = nullptr;
    nulls["subject_mapping"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<TokenExchangeTrustRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model TokenExchangeTrustResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"accepted_audiences": ["example"], "enabled": true, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"})json");

    const nlohmann::json encoded = minimal.get<TokenExchangeTrustResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["max_lifetime_secs"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<TokenExchangeTrustResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateFederationConfigRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateFederationConfigRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["allow_tenant_inheritance"] = nullptr;
    nulls["allowed_algorithms"] = nullptr;
    nulls["allowed_issuer_tenants"] = nullptr;
    nulls["apple_key_id"] = nullptr;
    nulls["apple_team_id"] = nullptr;
    nulls["attribute_map"] = nullptr;
    nulls["authorization_endpoint"] = nullptr;
    nulls["button_icon"] = nullptr;
    nulls["client_id"] = nullptr;
    nulls["client_secret"] = nullptr;
    nulls["enabled"] = nullptr;
    nulls["idp_signing_cert_pem"] = nullptr;
    nulls["metadata_url"] = nullptr;
    nulls["provider"] = nullptr;
    nulls["provider_slug"] = nullptr;
    nulls["require_pkce"] = nullptr;
    nulls["scopes"] = nullptr;
    nulls["token_endpoint"] = nullptr;
    nulls["token_exchange"] = nullptr;
    nulls["userinfo_endpoint"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateFederationConfigRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateGroup withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateGroup>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["metadata"] = nullptr;
    nulls["name"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateGroup>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateNotificationRuleRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateNotificationRuleRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["enabled"] = nullptr;
    nulls["events"] = nullptr;
    nulls["name"] = nullptr;
    nulls["recipient_emails"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateNotificationRuleRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateOAuth2ClientRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateOAuth2ClientRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["authn_request_params"] = nullptr;
    nulls["backchannel_logout_uri"] = nullptr;
    nulls["browser_sso"] = nullptr;
    nulls["dpop_bound_access_tokens"] = nullptr;
    nulls["dpop_require_nonce"] = nullptr;
    nulls["grant_types"] = nullptr;
    nulls["jwks"] = nullptr;
    nulls["jwks_uri"] = nullptr;
    nulls["name"] = nullptr;
    nulls["post_logout_redirect_uris"] = nullptr;
    nulls["profile"] = nullptr;
    nulls["redirect_uris"] = nullptr;
    nulls["require_par"] = nullptr;
    nulls["scopes"] = nullptr;
    nulls["self_signed_tls_client_auth_thumbprints"] = nullptr;
    nulls["tls_client_auth_san_dns"] = nullptr;
    nulls["tls_client_auth_san_uri"] = nullptr;
    nulls["tls_client_auth_subject_dn"] = nullptr;
    nulls["tls_client_certificate_bound_access_tokens"] = nullptr;
    nulls["token_endpoint_auth_method"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateOAuth2ClientRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateOrganizationRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateOrganizationRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    nulls["name"] = nullptr;
    nulls["slug"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateOrganizationRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdatePermissionRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdatePermissionRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["action"] = nullptr;
    nulls["description"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdatePermissionRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateReactorRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateReactorRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["enabled"] = nullptr;
    nulls["events"] = nullptr;
    nulls["failure_policy"] = nullptr;
    nulls["mode"] = nullptr;
    nulls["name"] = nullptr;
    nulls["priority"] = nullptr;
    nulls["timeout_ms"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateReactorRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateResourceRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateResourceRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    nulls["name"] = nullptr;
    nulls["parent_id"] = nullptr;
    nulls["resource_type"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateResourceRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateRole withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateRole>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["is_global"] = nullptr;
    nulls["name"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateRole>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateScopeRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateScopeRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["name"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateScopeRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateServiceAccount withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateServiceAccount>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["description"] = nullptr;
    nulls["name"] = nullptr;
    nulls["status"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateServiceAccount>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateTenant withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateTenant>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["metadata"] = nullptr;
    nulls["name"] = nullptr;
    nulls["slug"] = nullptr;
    nulls["status"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateTenant>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateUserRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateUserRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["email"] = nullptr;
    nulls["metadata"] = nullptr;
    nulls["status"] = nullptr;
    nulls["username"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateUserRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UpdateWebhookRequest withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({})json");

    const nlohmann::json encoded = minimal.get<UpdateWebhookRequest>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["enabled"] = nullptr;
    nulls["events"] = nullptr;
    nulls["retry_policy"] = nullptr;
    nulls["secret"] = nullptr;
    nulls["url"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UpdateWebhookRequest>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model UserResponse withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"})json");

    const nlohmann::json encoded = minimal.get<UserResponse>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["locked_until"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<UserResponse>();
    AXIAM_CHECK(from_nulls == minimal);
}

AXIAM_TEST("management model WebauthnAttestationPolicy withholds optionals it was not given") {
    // Every REQUIRED property, and not one optional property.
    const auto minimal = nlohmann::json::parse(
        R"json({"block_revoked_status": true, "mode": "none", "require_fido_certified": true})json");

    const nlohmann::json encoded = minimal.get<WebauthnAttestationPolicy>();
    // Byte-identical: an optional the server did not send must not reappear as a
    // default -- an empty string, a zero, a false -- that a later write would commit.
    AXIAM_CHECK(encoded == minimal);

    // An explicit JSON null says the same thing as an absent key, and must not be
    // read as a value.
    auto nulls = minimal;
    nulls["allowed_aaguids"] = nullptr;
    nulls["blocked_aaguids"] = nullptr;
    nulls["min_certification"] = nullptr;
    nulls["unknown_aaguid"] = nullptr;
    const nlohmann::json from_nulls = nulls.get<WebauthnAttestationPolicy>();
    AXIAM_CHECK(from_nulls == minimal);
}

// ---------------------------------------------------------------------------
// An optional collection the caller set to EMPTY. `tenant_scope` narrows a grant to
// named tenants; the server refuses an empty one with 400 rather than reading it as
// "no narrowing", so the SDK remembers it was given one and still withholds it.
// ---------------------------------------------------------------------------

AXIAM_TEST("management model AssignRoleToGroupRequest withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"group_id": "11111111-1111-4111-8111-111111111111", "tenant_scope": []})json");

    const auto value = wire.get<AssignRoleToGroupRequest>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model AssignRoleToServiceAccountRequest withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"service_account_id": "11111111-1111-4111-8111-111111111111", "tenant_scope": []})json");

    const auto value = wire.get<AssignRoleToServiceAccountRequest>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model AssignRoleToUserRequest withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"tenant_scope": [], "user_id": "11111111-1111-4111-8111-111111111111"})json");

    const auto value = wire.get<AssignRoleToUserRequest>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model RoleAssignment withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"role": {"created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "is_global": true, "name": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}, "tenant_scope": []})json");

    const auto value = wire.get<RoleAssignment>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model RoleGroupAssignment withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"group": {"created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}, "tenant_scope": []})json");

    const auto value = wire.get<RoleGroupAssignment>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model RoleServiceAccountAssignment withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"service_account": {"client_id": "example", "created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "name": "example", "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"}, "tenant_scope": []})json");

    const auto value = wire.get<RoleServiceAccountAssignment>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model RoleUserAssignment withholds an empty tenant_scope") {
    const auto wire = nlohmann::json::parse(
        R"json({"tenant_scope": [], "user": {"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "locked_until": "2026-08-26T00:00:00Z", "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"}})json");

    const auto value = wire.get<RoleUserAssignment>();
    // Decoded as present-and-empty, not as absent: the two are different requests and
    // the caller is entitled to see which one arrived.
    AXIAM_CHECK(value.tenant_scope.has_value());
    AXIAM_CHECK(value.tenant_scope->empty());

    // Encoding withholds it anyway -- an empty scope on the wire is a 400.
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.find("tenant_scope") == encoded.end());
    auto expected = wire;
    expected.erase("tenant_scope");
    AXIAM_CHECK(encoded == expected);
}

// ---------------------------------------------------------------------------
// Free-form JSON members (`metadata`, `scope_map`, `attribute_map`) are carried as
// raw TEXT -- the vendored parser is a private implementation detail, so the public
// header cannot name a JSON type. Text a caller assembled by hand may not parse. It
// is then dropped: splicing it in would put invalid JSON on the wire, and emitting
// it as a STRING would silently change the field's type under the server.
// ---------------------------------------------------------------------------

AXIAM_TEST("management model AuditLogEntry drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"action": "example", "actor_id": "11111111-1111-4111-8111-111111111111", "actor_type": "User", "id": "11111111-1111-4111-8111-111111111111", "ip_address": "example", "metadata": {}, "outcome": "Success", "resource_id": "11111111-1111-4111-8111-111111111111", "tenant_id": "11111111-1111-4111-8111-111111111111", "timestamp": "2026-08-26T00:00:00Z"})json");
    const nlohmann::json intact = wire.get<AuditLogEntry>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<AuditLogEntry>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model Certificate drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"cert_type": "User", "created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "metadata": {}, "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "public_cert_pem": "example", "status": "Active", "subject": "example", "tenant_id": "11111111-1111-4111-8111-111111111111"})json");
    const nlohmann::json intact = wire.get<Certificate>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<Certificate>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateCertificateRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"cert_type": "User", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "metadata": {}, "subject": "example", "validity_days": 1})json");
    const nlohmann::json intact = wire.get<CreateCertificateRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<CreateCertificateRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateFederationConfigRequest drops a attribute_map that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"allow_tenant_inheritance": true, "allowed_algorithms": ["example"], "allowed_issuer_tenants": ["example"], "apple_key_id": "example", "apple_team_id": "example", "attribute_map": {}, "authorization_endpoint": "example", "button_icon": "example", "client_id": "example", "client_secret": "example", "idp_signing_cert_pem": "example", "metadata_url": "example", "protocol": "example", "provider": "example", "provider_kind": "example", "provider_slug": "example", "require_pkce": true, "scopes": ["example"], "token_endpoint": "example", "token_exchange": {"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"}, "userinfo_endpoint": "example"})json");
    const nlohmann::json intact = wire.get<CreateFederationConfigRequest>();
    AXIAM_REQUIRE(intact.find("attribute_map") != intact.end());

    auto value = wire.get<CreateFederationConfigRequest>();
    value.attribute_map = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("attribute_map") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("attribute_map");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateGroupRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"description": "example", "metadata": {}, "name": "example"})json");
    const nlohmann::json intact = wire.get<CreateGroupRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<CreateGroupRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateResourceRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"metadata": {}, "name": "example", "parent_id": "11111111-1111-4111-8111-111111111111", "resource_type": "example"})json");
    const nlohmann::json intact = wire.get<CreateResourceRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<CreateResourceRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateTenantRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"metadata": {}, "name": "example", "slug": "example"})json");
    const nlohmann::json intact = wire.get<CreateTenantRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<CreateTenantRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model CreateUserRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"email": "example", "metadata": {}, "opaque": {"opaque_session": "example", "registration_record": "example"}, "password": "example", "username": "example"})json");
    const nlohmann::json intact = wire.get<CreateUserRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<CreateUserRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model FederationConfigResponse drops a attribute_map that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"allow_tenant_inheritance": true, "allowed_algorithms": ["example"], "allowed_issuer_tenants": ["example"], "apple_key_id": "example", "apple_team_id": "example", "attribute_map": {}, "authorization_endpoint": "example", "button_icon": "example", "client_id": "example", "created_at": "2026-08-26T00:00:00Z", "effective_scopes": ["example"], "enabled": true, "has_bundled_mark": true, "id": "11111111-1111-4111-8111-111111111111", "metadata_url": "example", "mints_client_secret": true, "pkce_required": true, "protocol": "example", "provider": "example", "provider_kind": "example", "provider_slug": "example", "scopes": ["example"], "tenant_id": "11111111-1111-4111-8111-111111111111", "token_endpoint": "example", "token_exchange": {"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"}, "updated_at": "2026-08-26T00:00:00Z", "userinfo_endpoint": "example"})json");
    const nlohmann::json intact = wire.get<FederationConfigResponse>();
    AXIAM_REQUIRE(intact.find("attribute_map") != intact.end());

    auto value = wire.get<FederationConfigResponse>();
    value.attribute_map = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("attribute_map") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("attribute_map");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model GeneratedCertificate drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"cert_type": "User", "chain_pem": "example", "created_at": "2026-08-26T00:00:00Z", "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111", "issuer_ca_id": "11111111-1111-4111-8111-111111111111", "key_algorithm": "Rsa4096", "metadata": {}, "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z", "private_key_pem": "example", "public_cert_pem": "example", "status": "Active", "subject": "example", "tenant_id": "11111111-1111-4111-8111-111111111111"})json");
    const nlohmann::json intact = wire.get<GeneratedCertificate>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<GeneratedCertificate>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model Group drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "description": "example", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z"})json");
    const nlohmann::json intact = wire.get<Group>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<Group>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model Organization drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "slug": "example", "updated_at": "2026-08-26T00:00:00Z"})json");
    const nlohmann::json intact = wire.get<Organization>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<Organization>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model Resource drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "metadata": {}, "name": "example", "parent_id": "11111111-1111-4111-8111-111111111111", "resource_type": "example", "tenant_id": "11111111-1111-4111-8111-111111111111", "uma_registered_by": "example", "updated_at": "2026-08-26T00:00:00Z"})json");
    const nlohmann::json intact = wire.get<Resource>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<Resource>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model Tenant drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "id": "11111111-1111-4111-8111-111111111111", "kind": "standard", "metadata": {}, "name": "example", "organization_id": "11111111-1111-4111-8111-111111111111", "slug": "example", "status": "Active", "updated_at": "2026-08-26T00:00:00Z"})json");
    const nlohmann::json intact = wire.get<Tenant>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<Tenant>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model TokenExchangeTrustRequest drops a scope_map that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"})json");
    const nlohmann::json intact = wire.get<TokenExchangeTrustRequest>();
    AXIAM_REQUIRE(intact.find("scope_map") != intact.end());

    auto value = wire.get<TokenExchangeTrustRequest>();
    value.scope_map = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("scope_map") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("scope_map");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model TokenExchangeTrustResponse drops a scope_map that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"})json");
    const nlohmann::json intact = wire.get<TokenExchangeTrustResponse>();
    AXIAM_REQUIRE(intact.find("scope_map") != intact.end());

    auto value = wire.get<TokenExchangeTrustResponse>();
    value.scope_map = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("scope_map") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("scope_map");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateFederationConfigRequest drops a attribute_map that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"allow_tenant_inheritance": true, "allowed_algorithms": ["example"], "allowed_issuer_tenants": ["example"], "apple_key_id": "example", "apple_team_id": "example", "attribute_map": {}, "authorization_endpoint": "example", "button_icon": "example", "client_id": "example", "client_secret": "example", "enabled": true, "idp_signing_cert_pem": "example", "metadata_url": "example", "provider": "example", "provider_slug": "example", "require_pkce": true, "scopes": ["example"], "token_endpoint": "example", "token_exchange": {"accepted_audiences": ["example"], "enabled": true, "max_lifetime_secs": 1, "max_token_age_secs": 1, "scope_map": {}, "subject_mapping": "example"}, "userinfo_endpoint": "example"})json");
    const nlohmann::json intact = wire.get<UpdateFederationConfigRequest>();
    AXIAM_REQUIRE(intact.find("attribute_map") != intact.end());

    auto value = wire.get<UpdateFederationConfigRequest>();
    value.attribute_map = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("attribute_map") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("attribute_map");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateGroup drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"description": "example", "metadata": {}, "name": "example"})json");
    const nlohmann::json intact = wire.get<UpdateGroup>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UpdateGroup>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateOrganizationRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"metadata": {}, "name": "example", "slug": "example"})json");
    const nlohmann::json intact = wire.get<UpdateOrganizationRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UpdateOrganizationRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateResourceRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"metadata": {}, "name": "example", "parent_id": "11111111-1111-4111-8111-111111111111", "resource_type": "example"})json");
    const nlohmann::json intact = wire.get<UpdateResourceRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UpdateResourceRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateTenant drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"metadata": {}, "name": "example", "slug": "example", "status": "Active"})json");
    const nlohmann::json intact = wire.get<UpdateTenant>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UpdateTenant>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UpdateUserRequest drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"email": "example", "metadata": {}, "status": "Active", "username": "example"})json");
    const nlohmann::json intact = wire.get<UpdateUserRequest>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UpdateUserRequest>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

AXIAM_TEST("management model UserResponse drops a metadata that is not JSON") {
    const auto wire = nlohmann::json::parse(
        R"json({"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "locked_until": "2026-08-26T00:00:00Z", "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"})json");
    const nlohmann::json intact = wire.get<UserResponse>();
    AXIAM_REQUIRE(intact.find("metadata") != intact.end());

    auto value = wire.get<UserResponse>();
    value.metadata = R"json({"unterminated": )json";
    const nlohmann::json encoded = value;

    AXIAM_CHECK(encoded.find("metadata") == encoded.end());
    // Exactly that one member is withheld; nothing else about the request shifts.
    auto expected = intact;
    expected.erase("metadata");
    AXIAM_CHECK(encoded == expected);
}

// ---------------------------------------------------------------------------
// Two shapes the fixtures above cannot state.
// ---------------------------------------------------------------------------

AXIAM_TEST("management model Certificate carries a bound_service_account_id when it has one") {
    // The generated fixture omits this member, so no test had ever taken the PRESENT side
    // of its encode guard -- a certificate bound to a service account is how an mTLS
    // machine identity is recognised, and dropping the binding on re-encode would unbind
    // it on the next write.
    const auto wire = nlohmann::json::parse(
        R"json({"bound_service_account_id": "22222222-2222-4222-8222-222222222222",)json"
        R"json( "cert_type": "User", "created_at": "2026-08-26T00:00:00Z",)json"
        R"json( "fingerprint": "example", "id": "11111111-1111-4111-8111-111111111111",)json"
        R"json( "issuer_ca_id": "11111111-1111-4111-8111-111111111111",)json"
        R"json( "key_algorithm": "Rsa4096", "metadata": {},)json"
        R"json( "not_after": "2026-08-26T00:00:00Z", "not_before": "2026-08-26T00:00:00Z",)json"
        R"json( "public_cert_pem": "example", "status": "Active", "subject": "example",)json"
        R"json( "tenant_id": "11111111-1111-4111-8111-111111111111"})json");

    const auto value = wire.get<Certificate>();
    AXIAM_REQUIRE(value.bound_service_account_id.has_value());
    AXIAM_CHECK(*value.bound_service_account_id == "22222222-2222-4222-8222-222222222222");

    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded == wire);
}

AXIAM_TEST("management model MdsRefreshOutcome encodes an empty object when its raw text is not JSON") {
    // A union is forwarded EXACTLY as received rather than re-encoded from the one member
    // this SDK models, so the carried text is whatever arrived. When it does not parse the
    // result is an empty object: the alternative is an invalid JSON body on the wire, and
    // nlohmann's discarded value serialises as `null`, which is not an object at all.
    const auto wire = nlohmann::json::parse(R"json({"entry_count": 1, "no": 1, "outcome": "initial"})json");
    auto value = wire.get<MdsRefreshOutcome>();
    AXIAM_CHECK(value.outcome == "initial");

    value.raw = "}{ not json";
    const nlohmann::json encoded = value;
    AXIAM_CHECK(encoded.is_object());
    AXIAM_CHECK(encoded.empty());
}

}  // namespace
