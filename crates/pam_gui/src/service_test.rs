use pam_client::service::ServiceError;

use crate::service::bridge_error;

#[test]
fn service_failures_keep_the_module_recovery_line() {
    let err = ServiceError::Unsupported { platform: "other" };
    let mapped = bridge_error(&err);
    assert_eq!(mapped.cause, "service_failed");
    assert_eq!(mapped.detail, "other has no login-start integration");
    assert_eq!(mapped.recovery, err.recovery());
}
