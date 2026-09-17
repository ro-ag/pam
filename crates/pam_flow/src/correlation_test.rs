use crate::{
    ArgValue, CorrelationTarget, FlowError, Vars, canonical_repository_url, digest, parse,
    to_normalized_yaml, validate_full_commit,
};

const SHA: &str = "abcdef1234567890abcdef1234567890abcdef12";
const HEAD: &str = "fedcba1234567890fedcba1234567890fedcba12";

fn yaml(declaration: &str) -> String {
    // Inputs ride along only when the declaration references them; an input
    // nothing reads is refused by validation.
    let inputs = if declaration.contains("${inputs.") {
        "inputs:\n  repository: {}\n  commit: {}\n  pr: {}\n  head: {}\n"
    } else {
        ""
    };
    format!(
        "schema: 1\nid: correlated\nname: Correlated\n{inputs}correlation:\n{declaration}\nsteps:\n  - id: inspect\n    run: [git, status]\n"
    )
}

fn literal() -> String {
    yaml(&format!(
        "  repository: https://github.com/team/project.git\n  commit: {SHA}"
    ))
}

fn reference_yaml() -> String {
    yaml(
        "  repository: '${inputs.repository}'\n  commit: '${inputs.commit}'\n  pull_request: '${inputs.pr}'\n  pull_request_head: '${inputs.head}'",
    )
}

fn vars() -> Vars {
    let mut vars = Vars::new();
    vars.set(
        "inputs.repository",
        "https://GITHUB.com:443/team/project.git",
    );
    vars.set("inputs.commit", SHA.to_ascii_uppercase());
    vars.set("inputs.pr", "42");
    vars.set("inputs.head", HEAD);
    vars
}

#[test]
fn existing_flows_remain_unbound_and_omit_the_declaration() {
    let flow = parse(
        "schema: 1\nid: unbound\nname: Unbound\nsteps:\n  - id: inspect\n    run: [git, status]\n",
    )
    .unwrap();
    assert!(flow.correlation.is_none());
    assert!(!to_normalized_yaml(&flow).contains("correlation"));
    assert!(
        serde_json::to_value(flow)
            .unwrap()
            .get("correlation")
            .is_none()
    );
}

#[test]
fn literal_targets_normalize_round_trip_and_change_the_digest() {
    let source = literal();
    let flow = parse(&source).unwrap();
    let equivalent = source
        .replace("https://github.com", "HTTPS://GITHUB.COM:443")
        .replace(SHA, &SHA.to_ascii_uppercase());
    let same = parse(&equivalent).unwrap();
    assert_eq!(flow, same);
    assert_eq!(digest(&flow), digest(&same));
    let normalized = to_normalized_yaml(&flow);
    assert_eq!(parse(&normalized).unwrap(), flow);
    assert!(normalized.find("correlation:").unwrap() < normalized.find("steps:").unwrap());
    for changed in [
        source.replace(SHA, HEAD),
        source.replace("github.com", "enterprise.example"),
        source.replace("project.git", "project"),
        source.replace("team/", "Team/"),
    ] {
        assert_ne!(digest(&flow), digest(&parse(&changed).unwrap()));
    }
}

#[test]
fn references_resolve_once_before_any_step_result_exists() {
    let flow = parse(&reference_yaml()).unwrap();
    let declaration = flow.correlation.unwrap();
    assert_eq!(
        declaration.references(),
        [
            "inputs.repository",
            "inputs.commit",
            "inputs.pr",
            "inputs.head"
        ]
    );
    let target = declaration.resolve(&vars()).unwrap();
    assert_eq!(target.repository, "https://github.com/team/project.git");
    assert_eq!(target.commit, SHA);
    assert_eq!(target.pull_request, Some(42));
    assert_eq!(target.pull_request_head.as_deref(), Some(HEAD));
    target.validate().unwrap();
    let restored: CorrelationTarget =
        serde_json::from_value(serde_json::to_value(&target).unwrap()).unwrap();
    restored.validate().unwrap();
    assert_eq!(restored, target);
    let mut values = vars();
    values.set("inputs.commit", "${steps.inspect.result.sha}");
    values.set_step("inspect", serde_json::json!({"result":{"sha":SHA}}));
    assert!(
        declaration.resolve(&values).is_err(),
        "input content must not be recursively resolved"
    );
    assert!(declaration.resolve(&Vars::new()).is_err());
}

#[test]
fn existing_repo_references_are_supported_without_inventing_new_slots() {
    let source = literal().replace("https://github.com/team/project.git", "${repo.origin}");
    let declaration = parse(&source).unwrap().correlation.unwrap();
    let mut values = Vars::new();
    values.set("repo.origin", "team/project");
    assert!(
        declaration.resolve(&values).is_err(),
        "a slug alone cannot identify a host"
    );
    values.set("repo.origin", "https://github.com/team/project.git");
    assert!(declaration.resolve(&values).is_ok());
    assert!(parse(&source.replace("repo.origin", "repo.url")).is_err());
}

#[test]
fn prior_step_unknown_and_interpolated_references_are_rejected() {
    for value in [
        "${steps.inspect.result.sha}",
        "${steps.inspect.exit_status}",
        "${inputs.missing}",
        "${inputs.commit}suffix",
        "prefix${inputs.commit}",
        "${inputs.commit}${inputs.head}",
        "${inputs.commit",
        "${repo.commit}",
        "${env.HOME}",
    ] {
        let error = parse(&literal().replace(SHA, value)).unwrap_err();
        assert!(matches!(error, FlowError::Invalid { path, .. } if path == "correlation.commit"));
    }
}

#[test]
fn sha_representation_is_full_nonzero_and_bounded_for_literals_and_inputs() {
    for bad in [
        "abc123",
        "HEAD",
        "main",
        &"0".repeat(40),
        &"g".repeat(40),
        &"a".repeat(39),
        &"a".repeat(41),
        &"a".repeat(65),
    ] {
        assert!(validate_full_commit(bad).is_err());
        assert!(parse(&literal().replace(SHA, &format!("'{bad}'"))).is_err());
        let declaration = parse(&reference_yaml()).unwrap().correlation.unwrap();
        let mut values = vars();
        values.set("inputs.commit", bad);
        assert!(declaration.resolve(&values).is_err());
    }
    assert_eq!(
        validate_full_commit(&"A".repeat(64)).unwrap(),
        "a".repeat(64)
    );
}

#[test]
fn pr_number_and_head_must_be_present_together_and_are_validated() {
    for extra in [
        "  pull_request: 42",
        &format!("  pull_request_head: {HEAD}"),
        &format!("  pull_request: 0\n  pull_request_head: {HEAD}"),
        &format!("  pull_request: -1\n  pull_request_head: {HEAD}"),
        "  pull_request: 42\n  pull_request_head: abc123",
    ] {
        assert!(parse(&literal().replace("\nsteps:", &format!("\n{extra}\nsteps:"))).is_err());
    }
    let numeric = literal().replace(
        "\nsteps:",
        &format!("\n  pull_request: 42\n  pull_request_head: {HEAD}\nsteps:"),
    );
    let flow = parse(&numeric).unwrap();
    assert_eq!(
        flow.correlation.as_ref().unwrap().pull_request,
        Some(ArgValue::Int(42))
    );
    assert_eq!(
        flow,
        parse(&numeric.replace("pull_request: 42", "pull_request: '42'")).unwrap()
    );
    let mut values = vars();
    for pr in ["0", "-1", "+42", "42 ", "9223372036854775808"] {
        values.set("inputs.pr", pr);
        assert!(
            parse(&reference_yaml())
                .unwrap()
                .correlation
                .unwrap()
                .resolve(&values)
                .is_err()
        );
    }
}

#[test]
fn repository_normalization_preserves_host_path_port_and_suffix_identity() {
    assert_eq!(
        canonical_repository_url("HTTPS://GitHub.COM:443/Team/Repo.git").unwrap(),
        "https://github.com/Team/Repo.git"
    );
    assert_eq!(
        canonical_repository_url("https://code.example:8443/team/repo.git").unwrap(),
        "https://code.example:8443/team/repo.git"
    );
    for bad in [
        "team/repo",
        "git@github.com:team/repo.git",
        "ssh://git@github.com/team/repo.git",
        "http://github.com/team/repo.git",
        "https://user:password@github.com/team/repo.git",
        "https://github.com/team/repo?token=value",
        "https://github.com/team/repo#main",
        "https://github.com/team/%2e%2e/repo",
        "https://github.com/team/../repo",
        "https://github.com/team//repo",
        "https://github.com/team/repo/",
        "https://github.com./team/repo",
        "https://github.com:0/team/repo",
        "https://github.com:65536/team/repo",
        "https://[::1]/team/repo",
        "https://127.01.0.1/team/repo",
        "https://github.com/team/ghp_example",
        "https://github.com/team/repo\n",
    ] {
        assert!(
            canonical_repository_url(bad).is_err(),
            "accepted ambiguous identity {bad}"
        );
    }
    assert!(canonical_repository_url(&format!("https://github.com/{}", "a".repeat(4096))).is_err());
}

#[test]
fn persisted_target_validation_rejects_noncanonical_and_incomplete_identity() {
    let target = parse(&reference_yaml())
        .unwrap()
        .correlation
        .unwrap()
        .resolve(&vars())
        .unwrap();
    let mut invalid = target.clone();
    invalid.repository = "https://GITHUB.COM/team/project.git".to_owned();
    assert!(invalid.validate().is_err());
    invalid = target.clone();
    invalid.commit = SHA.to_ascii_uppercase();
    assert!(invalid.validate().is_err());
    invalid = target.clone();
    invalid.pull_request_head = None;
    assert!(invalid.validate().is_err());
    let mut value = serde_json::to_value(target).unwrap();
    value["latest"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CorrelationTarget>(value).is_err());
}

#[test]
fn unknown_correlation_fields_are_rejected_and_errors_do_not_echo_credentials() {
    assert!(parse(&literal().replace("\nsteps:", "\n  latest: true\nsteps:")).is_err());
    let error =
        canonical_repository_url("https://user:private-sentinel@github.com/team/repo").unwrap_err();
    assert!(!error.to_string().contains("private-sentinel"));
}
