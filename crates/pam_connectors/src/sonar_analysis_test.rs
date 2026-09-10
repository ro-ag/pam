use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use serde_json::{Value, json};
use url::Url;

use crate::testing::FakeTransport;
use crate::{CallResult, Connection, ConnectorError, call};

const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";

fn catalog() -> FakeTransport {
    let services: Vec<Value> = [
        ("api/ce", "task", vec!["id"]),
        ("api/project_analyses", "search", vec!["project", "branch", "p", "ps"]),
        ("api/qualitygates", "project_status", vec!["analysisId"]),
    ].into_iter().map(|(path, action, keys)| json!({"path":path,"actions":[{"key":action,"params":keys.into_iter().map(|key| json!({"key":key})).collect::<Vec<_>>()}]})).collect();
    FakeTransport::new().json(200, &json!({"webServices":services}).to_string())
}

fn task(status: &str) -> Value {
    let mut task = json!({"id":"task-1","type":"REPORT","componentKey":"project","status":status,"branch":"main"});
    if status == "SUCCESS" {
        task["analysisId"] = json!("analysis-1");
    }
    json!({"task":task})
}

fn history() -> Value {
    json!({"paging":{"pageIndex":1,"pageSize":100,"total":1},"analyses":[{"key":"analysis-1","revision":SHA}]})
}

fn gate() -> Value {
    json!({"projectStatus":{"status":"ERROR","conditions":[{"metricKey":"new_coverage","status":"ERROR","comparator":"LT","actualValue":"61.4","errorThreshold":"80"}],"period":{"mode":"REFERENCE_BRANCH","parameter":"main"},"ignoredConditions":true,"caycStatus":"non-compliant"}})
}

fn responses(task: &Value, history: &Value, gate: &Value) -> FakeTransport {
    catalog()
        .json(200, &task.to_string())
        .json(200, &history.to_string())
        .json(200, &gate.to_string())
}

fn args() -> BTreeMap<String, ArgValue> {
    [
        ("project", "project"),
        ("ce_task", "task-1"),
        ("branch", "main"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), ArgValue::Text(v.to_owned())))
    .collect()
}

async fn run(
    args: &BTreeMap<String, ArgValue>,
    transport: &FakeTransport,
) -> Result<Value, ConnectorError> {
    let connection = Connection {
        base_url: Url::parse("https://sonar.example/").unwrap(),
        username: None,
        secret: None,
    };
    match call(
        ConnectorId::Sonarqube,
        &connection,
        "analysis",
        args,
        transport,
        Instant::now() + Duration::from_secs(10),
    )
    .await?
    {
        CallResult::Json(value) => Ok(value),
        CallResult::Log { .. } => panic!("analysis must return JSON"),
    }
}

#[tokio::test]
async fn historical_gate_is_pinned_even_when_a_newer_analysis_is_green() {
    let history = json!({"paging":{"total":2},"analyses":[{"key":"newer-green","revision":"1111111111111111111111111111111111111111"},{"key":"analysis-1","revision":SHA}]});
    let transport = responses(&task("SUCCESS"), &history, &gate());
    let result = run(&args(), &transport).await.unwrap();
    assert_eq!(result["status"], "ERROR");
    assert_eq!(result["analysis_id"], "analysis-1");
    assert_eq!(result["revision"], SHA);
    assert_eq!(result["partial"], false);
    assert_eq!(transport.requests().len(), 4);
    assert!(transport.url(0).ends_with("?include_internals=true"));
    assert_eq!(
        transport.url(3),
        "https://sonar.example/api/qualitygates/project_status?analysisId=analysis-1"
    );
    assert_eq!(result["conditions"][0]["comparator"], "LT");
    assert_eq!(result["conditions"][0]["actual"], "61.4");
    assert_eq!(result["conditions"][0]["threshold"], "80");
    assert_eq!(result["period"]["mode"], "REFERENCE_BRANCH");
    assert_eq!(result["ignored_conditions"], true);
    assert_eq!(result["cayc_status_current"], "non-compliant");
}

#[tokio::test]
async fn incomplete_and_failed_ce_tasks_do_not_read_a_gate() {
    for status in ["PENDING", "IN_PROGRESS", "FAILED", "CANCELED"] {
        let transport = catalog().json(200, &task(status).to_string());
        let result = run(&args(), &transport).await.unwrap();
        assert_eq!(result["status"], status);
        assert_eq!(result["revision_basis"], "ce_not_complete");
        assert!(result["analysis_id"].is_null());
        assert_eq!(transport.requests().len(), 2);
    }
}

#[tokio::test]
async fn conflicting_or_incomplete_task_identity_stops_collection() {
    for (key, value) in [
        ("id", json!("other")),
        ("componentKey", json!("other")),
        ("branch", json!("other")),
        ("type", json!("OTHER")),
        ("analysisId", Value::Null),
    ] {
        let mut task = task("SUCCESS");
        task["task"][key] = value;
        let transport = catalog().json(200, &task.to_string());
        assert!(matches!(
            run(&args(), &transport).await,
            Err(ConnectorError::BadResponse(_))
        ));
        assert_eq!(transport.requests().len(), 2);
    }
}

#[tokio::test]
async fn explicit_second_page_can_resolve_the_exact_analysis_without_complete_history() {
    let transport = responses(
        &task("SUCCESS"),
        &json!({"paging":{"pageIndex":2,"pageSize":100,"total":101},"analyses":[{"key":"analysis-1","revision":SHA}]}),
        &gate(),
    );
    let mut args = args();
    args.insert("page".to_owned(), ArgValue::Int(2));
    let result = run(&args, &transport).await.unwrap();
    assert_eq!(result["revision"], SHA);
    assert_eq!(result["partial"], false);
    assert_eq!(result["coverage"]["partial"], true);
    assert!(transport.url(2).contains("p=2&ps=100"));
}

#[tokio::test]
async fn absence_invalid_revision_and_oversized_pages_never_borrow_another_commit() {
    let mut oversized = vec![json!({"key":"analysis-1","revision":SHA})];
    oversized.extend((0..100).map(|i| json!({"key":format!("other-{i}"),"revision":SHA})));
    for history in [
        json!({"analyses":[]}),
        json!({"analyses":[{"key":"analysis-1"}]}),
        json!({"analyses":[{"key":"analysis-1","revision":"abcdef1"}]}),
        json!({"analyses":oversized}),
    ] {
        let transport = responses(&task("SUCCESS"), &history, &gate());
        let result = run(&args(), &transport).await.unwrap();
        assert!(result["revision"].is_null());
        assert_eq!(result["status"], "ERROR");
        assert_eq!(result["partial"], true);
        assert!(result["coverage"]["returned"].as_u64().unwrap() <= 100);
    }
}

#[tokio::test]
async fn pr_gate_remains_exact_but_revision_is_explicitly_unsupported() {
    let mut task = task("SUCCESS");
    task["task"].as_object_mut().unwrap().remove("branch");
    task["task"]["pullRequest"] = json!("42");
    let transport = catalog()
        .json(200, &task.to_string())
        .json(200, &gate().to_string());
    let mut args = args();
    args.remove("branch");
    args.insert("pullRequest".to_owned(), ArgValue::Text("42".to_owned()));
    let result = run(&args, &transport).await.unwrap();
    assert_eq!(transport.requests().len(), 3);
    assert_eq!(result["revision_basis"], "pull_request_unsupported");
    assert_eq!(result["partial"], true);
    assert_eq!(result["status"], "ERROR");
}

#[tokio::test]
async fn capability_and_permission_failures_do_not_fall_back_to_live_measures() {
    let transport = FakeTransport::new().json(200, r#"{"webServices":[]}"#);
    assert_eq!(
        run(&args(), &transport).await.unwrap_err().cause(),
        "sonarqube_contract_unavailable"
    );
    assert_eq!(transport.requests().len(), 1);
    for status in [403, 404] {
        let transport = catalog()
            .json(200, &task("SUCCESS").to_string())
            .json(200, &history().to_string())
            .json(status, "{}");
        assert!(run(&args(), &transport).await.is_err());
        assert_eq!(transport.requests().len(), 4);
    }
}

#[tokio::test]
async fn conditions_and_summary_are_bounded_without_hiding_unreported_failures() {
    let mut gate = gate();
    gate["projectStatus"]["conditions"] = json!((0..20).map(|i| json!({"metricKey":format!("metric-{i}{}","界".repeat(300)),"status":"ERROR","comparator":"GT","actualValue":"9","errorThreshold":"1"})).collect::<Vec<_>>());
    let transport = responses(&task("SUCCESS"), &history(), &gate);
    let result = run(&args(), &transport).await.unwrap();
    assert_eq!(result["conditions"].as_array().unwrap().len(), 20);
    let summary = result["summary"].as_str().unwrap();
    assert!(summary.len() <= 6000);
    assert!(summary.contains("12 further failing/warning conditions omitted"));
    assert!(summary.contains("[truncated]"));
    gate["projectStatus"]["conditions"] = json!(vec![json!({"status":"ERROR"}); 101]);
    assert!(
        run(&args(), &responses(&task("SUCCESS"), &history(), &gate))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_history_gate_and_arguments_fail_before_fallback() {
    for history in [
        json!({"paging":{"pageIndex":2},"analyses":[]}),
        json!({"analyses":[{"key":"analysis-1","revision":SHA},{"key":"analysis-1","revision":SHA}]}),
    ] {
        let transport = responses(&task("SUCCESS"), &history, &gate());
        assert!(run(&args(), &transport).await.is_err());
        assert_eq!(transport.requests().len(), 3);
    }
    for change in [
        json!({"analysisId":"wrong","projectStatus":{"status":"OK","conditions":[]}}),
        json!({"projectStatus":{"status":"PASS","conditions":[]}}),
    ] {
        assert!(
            run(&args(), &responses(&task("SUCCESS"), &history(), &change))
                .await
                .is_err()
        );
    }
    let transport = FakeTransport::new();
    let mut args = args();
    args.insert("ce_task".to_owned(), ArgValue::Text("../evil".to_owned()));
    assert!(run(&args, &transport).await.is_err());
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn no_gate_and_conflicting_gate_project_remain_distinct() {
    let transport = responses(
        &task("SUCCESS"),
        &history(),
        &json!({"projectStatus":{"status":"NONE"}}),
    );
    let result = run(&args(), &transport).await.unwrap();
    assert_eq!(result["status"], "NONE");
    assert_eq!(result["conditions"], json!([]));
    let transport = responses(
        &task("SUCCESS"),
        &history(),
        &json!({"project":"other","projectStatus":{"status":"OK","conditions":[]}}),
    );
    assert!(run(&args(), &transport).await.is_err());
}

#[tokio::test]
async fn unavailable_scoped_history_keeps_the_pinned_gate_without_an_unfiltered_retry() {
    let catalog_without_branch = json!({"webServices":[
        {"path":"api/ce","actions":[{"key":"task","params":[{"key":"id"}]}]},
        {"path":"api/project_analyses","actions":[{"key":"search","params":[{"key":"project"},{"key":"p"},{"key":"ps"}]}]},
        {"path":"api/qualitygates","actions":[{"key":"project_status","params":[{"key":"analysisId"}]}]}
    ]});
    let transport = FakeTransport::new()
        .json(200, &catalog_without_branch.to_string())
        .json(200, &task("SUCCESS").to_string())
        .json(200, &gate().to_string());
    let result = run(&args(), &transport).await.unwrap();
    assert_eq!(result["status"], "ERROR");
    assert_eq!(result["analysis_id"], "analysis-1");
    assert!(result["revision"].is_null());
    assert_eq!(result["gaps"], json!(["history_contract_unavailable"]));
    assert_eq!(transport.requests().len(), 3);
    assert!(transport.url(2).ends_with("?analysisId=analysis-1"));
}

#[tokio::test]
async fn history_permissions_and_transport_failures_retain_exact_gate_evidence() {
    for (status, cause) in [
        (403, "history_connector_forbidden"),
        (404, "history_connector_not_found"),
    ] {
        let transport = catalog()
            .json(200, &task("SUCCESS").to_string())
            .json(status, "{}")
            .json(200, &gate().to_string());
        let result = run(&args(), &transport).await.unwrap();
        assert_eq!(result["ce_task"], "task-1");
        assert_eq!(result["status"], "ERROR");
        assert_eq!(result["partial"], true);
        assert!(result["revision"].is_null());
        assert_eq!(result["gaps"], json!([cause]));
        assert_eq!(transport.requests().len(), 4);
    }
    let transport = catalog()
        .json(200, &task("SUCCESS").to_string())
        .failure(crate::TransportError::Network("unreachable".to_owned()))
        .json(200, &gate().to_string());
    let result = run(&args(), &transport).await.unwrap();
    assert_eq!(result["status"], "ERROR");
    assert_eq!(result["gaps"], json!(["history_connector_network"]));
}
