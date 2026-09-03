use serde_json::json;

use super::vars::{VarError, Vars, references, substitute};

fn vars() -> Vars {
    let mut vars = Vars::new();
    vars.set("inputs.repo", "ro-ag/pam");
    vars.set("repo.path", "/home/dev/pam");
    vars.set("repo.name", "pam");
    vars.set_step(
        "latest-failed",
        json!({
            "result": { "jobs": [ { "id": 42, "name": "clippy" } ], "partial": false },
            "exit_status": 101,
        }),
    );
    vars
}

#[test]
fn references_lists_every_key_in_order() {
    assert_eq!(
        references("${inputs.repo} and ${repo.name} and ${inputs.repo}"),
        ["inputs.repo", "repo.name", "inputs.repo"]
    );
    assert!(references("nothing to see").is_empty());
}

#[test]
fn an_unterminated_reference_is_literal_text() {
    assert!(references("${inputs.repo").is_empty());
    assert!(references("$ {inputs.repo}").is_empty());
    assert_eq!(
        substitute("${inputs.repo", &vars()),
        Ok("${inputs.repo".to_string())
    );
}

#[test]
fn substitutes_inputs_and_repo_variables() {
    assert_eq!(
        substitute("--repo=${inputs.repo}", &vars()),
        Ok("--repo=ro-ag/pam".to_string())
    );
    assert_eq!(
        substitute("${repo.path}/target", &vars()),
        Ok("/home/dev/pam/target".to_string())
    );
    assert_eq!(substitute("plain", &vars()), Ok("plain".to_string()));
}

#[test]
fn substitutes_step_results_through_a_pointer() {
    assert_eq!(
        substitute("${steps.latest-failed.result.jobs[0].id}", &vars()),
        Ok("42".to_string())
    );
    assert_eq!(
        substitute("${steps.latest-failed.result.jobs[0].name}", &vars()),
        Ok("clippy".to_string())
    );
    assert_eq!(
        substitute("${steps.latest-failed.result.partial}", &vars()),
        Ok("false".to_string())
    );
    assert_eq!(
        substitute("${steps.latest-failed.exit_status}", &vars()),
        Ok("101".to_string())
    );
}

#[test]
fn an_unresolved_reference_names_the_key() {
    let err = substitute("${inputs.missing}", &vars()).expect_err("unresolved");
    assert_eq!(
        err,
        VarError::Unresolved {
            key: "inputs.missing".to_string()
        }
    );
    assert!(err.to_string().contains("${inputs.missing}"), "{err}");

    for key in [
        "steps.absent.result.id",
        "steps.latest-failed.result.jobs[9].id",
        "steps.latest-failed.result.jobs[0].missing",
        "steps.latest-failed.result.jobs.id",
        "",
    ] {
        let text = format!("${{{key}}}");
        assert_eq!(
            substitute(&text, &vars()),
            Err(VarError::Unresolved {
                key: key.to_string()
            }),
            "{key} should not resolve"
        );
    }
}

#[test]
fn arrays_and_objects_do_not_stringify() {
    assert!(substitute("${steps.latest-failed.result}", &vars()).is_err());
    assert!(substitute("${steps.latest-failed.result.jobs}", &vars()).is_err());
}

#[test]
fn substituted_values_are_never_re_parsed() {
    let mut vars = Vars::new();
    vars.set("inputs.repo", "${repo.name}");
    vars.set("repo.name", "pam");
    assert_eq!(
        substitute("${inputs.repo}", &vars),
        Ok("${repo.name}".to_string())
    );
}

#[test]
fn resolve_answers_one_key_at_a_time() {
    assert_eq!(vars().resolve("inputs.repo").as_deref(), Some("ro-ag/pam"));
    assert_eq!(vars().resolve("inputs.nope"), None);
    assert_eq!(
        vars().resolve("steps.latest-failed.exit_status").as_deref(),
        Some("101")
    );
}
