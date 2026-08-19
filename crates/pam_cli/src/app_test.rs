use std::path::Path;

use crate::{
    app::{audit_export, retention_prune},
    command::RetentionScopeArg,
    render::EXIT_OPERATION_FAILED,
};

#[tokio::test]
async fn administrative_storage_ranges_are_rejected_before_local_authorization() {
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), u64::MAX, None, None, 1).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), 0, Some(u64::MAX), None, 1,).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        retention_prune(RetentionScopeArg::Session, u64::MAX, None, 1).await,
        EXIT_OPERATION_FAILED
    );
}
