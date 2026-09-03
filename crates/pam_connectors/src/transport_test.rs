use std::collections::BTreeMap;

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::transport::{
    AWS_BASE_URL, Connection, HttpResponse, Secret, base64, check_status, endpoint, id_arg,
    int_arg, opt_text_arg, parse_json, pick, request, string_field, text_arg, validate_base_url,
};
use crate::{ConnectorError, MAX_JSON_BYTES};

#[test]
fn a_base_url_gains_a_trailing_slash() {
    let url = validate_base_url(ConnectorId::Github, "https://api.github.com").unwrap();
    assert_eq!(url.as_str(), "https://api.github.com/");
    let nested = validate_base_url(ConnectorId::Jenkins, "https://ci.example.com/jenkins").unwrap();
    assert_eq!(nested.as_str(), "https://ci.example.com/jenkins/");
}

#[test]
fn a_base_url_must_be_https_without_credentials_query_or_fragment() {
    for raw in [
        "http://ci.example.com",
        "ftp://ci.example.com",
        "https://user:pass@ci.example.com",
        "https://ci.example.com/?token=abc",
        "https://ci.example.com/#top",
        "not a url",
        "   ",
    ] {
        let error = validate_base_url(ConnectorId::Jenkins, raw).unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{raw} was accepted");
    }
}

#[test]
fn private_and_loopback_hosts_are_fine() {
    // Self-hosted Jenkins and SonarQube live there; the human typed it.
    for raw in ["https://localhost:8080", "https://10.0.0.7/sonar"] {
        assert!(
            validate_base_url(ConnectorId::Sonarqube, raw).is_ok(),
            "{raw}"
        );
    }
}

#[test]
fn aws_keeps_no_base_url() {
    let url = validate_base_url(ConnectorId::Aws, "").unwrap();
    assert_eq!(url.as_str(), AWS_BASE_URL);
    assert!(validate_base_url(ConnectorId::Github, "").is_err());
}

#[test]
fn endpoints_join_onto_the_base_path_without_doubling_the_slash() {
    let base = validate_base_url(ConnectorId::Jenkins, "https://ci.example.com/jenkins").unwrap();
    let url = endpoint(&base, &["job", "platform", "api", "json"]).unwrap();
    assert_eq!(
        url.as_str(),
        "https://ci.example.com/jenkins/job/platform/api/json"
    );
}

#[test]
fn endpoint_segments_are_percent_encoded() {
    let base = validate_base_url(ConnectorId::Jira, "https://jira.example.com").unwrap();
    let url = endpoint(&base, &["rest", "api", "2", "issue", "a b/c"]).unwrap();
    assert!(url.as_str().ends_with("/issue/a%20b%2Fc"), "{url}");
}

#[test]
fn base64_matches_the_reference_vectors() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foob"), "Zm9vYg==");
    assert_eq!(base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"user:token"), "dXNlcjp0b2tlbg==");
}

#[test]
fn a_bearer_connector_sends_the_secret_in_one_header() {
    let http = request(
        ConnectorId::Github,
        &github(),
        url("https://api.github.com/user"),
        16,
    )
    .unwrap();
    assert_eq!(
        header(&http.headers, "authorization"),
        Some("Bearer ghp_secret".to_owned())
    );
    assert_eq!(
        header(&http.headers, "x-github-api-version"),
        Some("2022-11-28".to_owned())
    );
    assert_eq!(
        header(&http.headers, "accept"),
        Some("application/json".to_owned())
    );
    assert!(header(&http.headers, "user-agent").is_some_and(|agent| agent.starts_with("pam/")));
    assert!(!http.follow_one_https_redirect_without_auth);
}

#[test]
fn basic_auth_uses_the_username_and_a_token_as_user_leaves_the_password_empty() {
    let jenkins = Connection {
        base_url: url("https://ci.example.com/"),
        username: Some("ci-bot".to_owned()),
        secret: Some(Secret::new("t0ken".to_owned())),
    };
    let http = request(
        ConnectorId::Jenkins,
        &jenkins,
        url("https://ci.example.com/"),
        16,
    )
    .unwrap();
    assert_eq!(
        header(&http.headers, "authorization"),
        Some(format!("Basic {}", base64(b"ci-bot:t0ken")))
    );

    let sonar = Connection {
        base_url: url("https://sonar.example.com/"),
        username: None,
        secret: Some(Secret::new("squ_abc".to_owned())),
    };
    let http = request(
        ConnectorId::Sonarqube,
        &sonar,
        url("https://sonar.example.com/"),
        16,
    )
    .unwrap();
    assert_eq!(
        header(&http.headers, "authorization"),
        Some(format!("Basic {}", base64(b"squ_abc:")))
    );
}

#[test]
fn a_missing_credential_is_an_auth_failure_before_any_request() {
    let bare = Connection {
        base_url: url("https://api.github.com/"),
        username: None,
        secret: None,
    };
    let error = request(
        ConnectorId::Github,
        &bare,
        url("https://api.github.com/user"),
        16,
    )
    .unwrap_err();
    assert_eq!(error, ConnectorError::Auth);
}

#[test]
fn aws_makes_no_http_requests() {
    let aws = Connection {
        base_url: url(AWS_BASE_URL),
        username: Some("default".to_owned()),
        secret: None,
    };
    let error = request(ConnectorId::Aws, &aws, url(AWS_BASE_URL), 16).unwrap_err();
    assert_eq!(error.cause(), "connector_bad_args");
}

#[test]
fn a_secret_never_prints_itself() {
    let secret = Secret::new("ghp_do_not_print".to_owned());
    assert_eq!(format!("{secret:?}"), "[REDACTED]");
    assert_eq!(secret.expose(), "ghp_do_not_print");
    assert!(!format!("{:?}", github()).contains("ghp_secret"));
}

#[test]
fn statuses_map_onto_the_shared_refusals() {
    assert!(check_status(&answer(200, &[])).is_ok());
    assert!(check_status(&answer(204, &[])).is_ok());
    assert_eq!(check_status(&answer(401, &[])), Err(ConnectorError::Auth));
    assert_eq!(
        check_status(&answer(403, &[])),
        Err(ConnectorError::Forbidden)
    );
    assert_eq!(
        check_status(&answer(404, &[])),
        Err(ConnectorError::NotFound)
    );
    assert_eq!(
        check_status(&answer(500, &[])),
        Err(ConnectorError::Remote { status: 500 })
    );
    assert_eq!(
        check_status(&answer(302, &[])).unwrap_err().cause(),
        "connector_bad_response"
    );
    assert_eq!(
        check_status(&answer(400, &[])).unwrap_err().cause(),
        "connector_bad_args"
    );
}

#[test]
fn an_exhausted_rate_limit_budget_turns_a_403_into_throttling() {
    let response = answer(403, &[("x-ratelimit-remaining", "0")]);
    assert_eq!(
        check_status(&response),
        Err(ConnectorError::RateLimited { retry_after: None })
    );
    let with_budget = answer(403, &[("x-ratelimit-remaining", "12")]);
    assert_eq!(check_status(&with_budget), Err(ConnectorError::Forbidden));
}

#[test]
fn retry_after_is_read_off_a_429() {
    let response = answer(429, &[("Retry-After", "60")]);
    let ConnectorError::RateLimited { retry_after } = check_status(&response).unwrap_err() else {
        panic!("a 429 is throttling");
    };
    assert_eq!(retry_after, Some(std::time::Duration::from_mins(1)));
}

#[test]
fn a_body_over_the_budget_is_refused_before_it_is_parsed() {
    let body = vec![b'x'; 32];
    let error = parse_json(&body, 16).unwrap_err();
    assert_eq!(
        error,
        ConnectorError::TooLarge {
            bytes: 32,
            maximum: 16
        }
    );
    assert!(parse_json(b"not json", MAX_JSON_BYTES).is_err());
    assert_eq!(parse_json(b"{\"a\":1}", MAX_JSON_BYTES).unwrap()["a"], 1);
}

#[test]
fn arguments_are_read_with_their_own_refusals() {
    let mut args = BTreeMap::new();
    args.insert("repo".to_owned(), ArgValue::Text("ro-ag/pam".to_owned()));
    args.insert("limit".to_owned(), ArgValue::Int(7));
    args.insert("blank".to_owned(), ArgValue::Text("  ".to_owned()));

    assert_eq!(text_arg(&args, "repo").unwrap(), "ro-ag/pam");
    assert_eq!(opt_text_arg(&args, "missing").unwrap(), None);
    assert!(text_arg(&args, "blank").is_err());
    assert!(text_arg(&args, "limit").is_err());
    assert!(text_arg(&args, "missing").is_err());

    assert_eq!(int_arg(&args, "limit", 5, (1, 100)).unwrap(), 7);
    assert_eq!(int_arg(&args, "missing", 5, (1, 100)).unwrap(), 5);
    assert!(int_arg(&args, "limit", 5, (1, 5)).is_err());
    assert!(int_arg(&args, "repo", 5, (1, 100)).is_err());

    assert_eq!(id_arg(&args, "limit").unwrap(), 7);
    assert!(id_arg(&args, "missing").is_err());

    let mut digits = BTreeMap::new();
    digits.insert("run_id".to_owned(), ArgValue::Text("42".to_owned()));
    digits.insert("negative".to_owned(), ArgValue::Int(-1));
    assert_eq!(id_arg(&digits, "run_id").unwrap(), 42);
    assert!(id_arg(&digits, "negative").is_err());
}

#[test]
fn picked_fields_are_the_only_ones_that_travel() {
    let value = serde_json::json!({ "id": 4, "name": "build", "secret": "no" });
    let picked = pick(&value, &["id", "name", "missing"]);
    assert_eq!(picked["id"], 4);
    assert_eq!(picked["name"], "build");
    assert!(picked["missing"].is_null());
    assert!(picked.get("secret").is_none());
}

#[test]
fn a_missing_string_field_names_itself() {
    let value = serde_json::json!({ "login": "" });
    let error = string_field(&value, "login").unwrap_err();
    assert!(error.detail().contains("login"), "{error:?}");
}

fn github() -> Connection {
    Connection {
        base_url: url("https://api.github.com/"),
        username: None,
        secret: Some(Secret::new("ghp_secret".to_owned())),
    }
}

fn url(raw: &str) -> Url {
    Url::parse(raw).expect("the test URL parses")
}

fn answer(status: u16, headers: &[(&str, &str)]) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: b"{}".to_vec(),
    }
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}
