use serde_json::json;

use super::vars::{ArgvError, VarError, Vars, references, substitute, substitute_argv};

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

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn a_supplied_value_cannot_become_an_option() {
    let mut vars = Vars::new();
    vars.set("inputs.rev", "--output=/tmp/planted");
    vars.set("inputs.script", "-e");
    vars.set("inputs.empty", "");
    for (template, position) in [
        (argv(&["git", "log", "${inputs.rev}"]), 2),
        (argv(&["node", "${inputs.script}", "x"]), 1),
        // An empty leading value does not hide the dash behind it.
        (argv(&["git", "log", "${inputs.empty}${inputs.script}"]), 2),
    ] {
        assert_eq!(
            substitute_argv(&template, &vars),
            Err(ArgvError::Option { position }),
            "{template:?}"
        );
    }
}

#[test]
fn the_template_itself_may_mark_an_option_or_end_them() {
    let mut vars = Vars::new();
    vars.set("inputs.rev", "--output=/tmp/planted");
    vars.set("inputs.day", "-1 day");
    vars.set("inputs.plain", "main");
    // After the author's `--`, everything is an operand.
    assert_eq!(
        substitute_argv(&argv(&["git", "log", "--", "${inputs.rev}"]), &vars).unwrap(),
        argv(&["git", "log", "--", "--output=/tmp/planted"])
    );
    // Literal text in front confines the value to that option's argument.
    assert_eq!(
        substitute_argv(&argv(&["git", "log", "--since=${inputs.day}"]), &vars).unwrap(),
        argv(&["git", "log", "--since=-1 day"])
    );
    assert_eq!(
        substitute_argv(&argv(&["git", "log", "${inputs.plain}", "-20"]), &vars).unwrap(),
        argv(&["git", "log", "main", "-20"])
    );
}

#[test]
fn a_substituted_double_dash_does_not_end_option_parsing() {
    let mut vars = Vars::new();
    vars.set("inputs.sep", "--");
    vars.set("inputs.rev", "--output=/tmp/planted");
    // The first value is itself refused; were it allowed, the second would ride on it.
    assert_eq!(
        substitute_argv(
            &argv(&["git", "log", "${inputs.sep}", "${inputs.rev}"]),
            &vars
        ),
        Err(ArgvError::Option { position: 2 })
    );
}

#[test]
fn an_unfilled_argument_names_its_position() {
    assert_eq!(
        substitute_argv(&argv(&["git", "log", "${inputs.nope}"]), &Vars::new()),
        Err(ArgvError::Unresolved {
            position: 2,
            source: VarError::Unresolved {
                key: "inputs.nope".to_owned()
            }
        })
    );
}
