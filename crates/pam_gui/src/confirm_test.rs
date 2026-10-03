use serde_json::{Value, json};

use crate::bridge::required_confirmation;
use crate::confirm::{
    ALLOW_LABEL, CANCEL_LABEL, CAUSE_CONFIRMATION_DECLINED, PROMPT_TITLE, declined, prompt_for,
    shown,
};

fn body(op: &str, args: &Value) -> String {
    let prompt = prompt_for(op, args, None);
    assert_eq!(prompt.title, PROMPT_TITLE);
    prompt.body
}

#[test]
fn the_dialog_speaks_plainly_with_allow_and_cancel() {
    assert_eq!(PROMPT_TITLE, "Confirm in PAM");
    assert_eq!(ALLOW_LABEL, "Allow");
    assert_eq!(CANCEL_LABEL, "Cancel");
}

#[test]
fn relaxing_the_profile_says_what_relaxed_means() {
    assert_eq!(
        body("admin.profile.set", &json!({"profile": "relaxed"})),
        "Relax the security profile to relaxed. Safe capabilities will then grant themselves \
         the first time an agent uses them, without asking you."
    );
    // The fail-closed cases the phrase rule guards get a sentence too.
    let unknown = body("admin.profile.set", &json!({"profile": "open"}));
    assert!(
        unknown.starts_with("Change the security profile to \u{201C}open\u{201D}."),
        "{unknown}"
    );
    let unreadable = body("admin.profile.set", &json!({}));
    assert!(unreadable.contains("one PAM cannot read"), "{unreadable}");
}

#[test]
fn a_grant_names_the_capability_and_its_reach() {
    assert_eq!(
        body("admin.grants.add", &json!({"capability": "fs.write"})),
        "Grant \u{201C}fs.write\u{201D} to every agent in every repository. Agents can then use \
         it without asking you, until you revoke it in Settings."
    );
    let bound = body(
        "admin.grants.add",
        &json!({"capability": "flow.step:land/merge", "repository": "/src/app"}),
    );
    assert!(
        bound.starts_with(
            "Grant \u{201C}flow.step:land/merge\u{201D} to every agent in the repository \
             \u{201C}/src/app\u{201D}."
        ),
        "{bound}"
    );
}

#[test]
fn remembering_an_approval_uses_the_daemons_entry_not_the_webviews_words() {
    let args = json!({"request_id": "req_7", "resolution": "approved", "remember": true});
    // Without the daemon's entry the dialog names the request and the standing effect.
    assert_eq!(
        body("admin.approvals.resolve", &args),
        "Approve \u{201C}req_7\u{201D} and remember the answer. Agents can then use what it asked \
         for again without asking you, until you revoke it in Settings."
    );
    // A plain capability: the grant is global.
    let plain = json!({"request_id": "req_7", "capability": "net.fetch", "remember": null});
    assert_eq!(
        prompt_for("admin.approvals.resolve", &args, Some(&plain)).body,
        "Approve this request and remember the answer. Every agent in every repository can then \
         use \u{201C}net.fetch\u{201D} without asking you, until you revoke it in Settings."
    );
    // A gated flow step: the scope the daemon will record.
    let step = json!({
        "request_id": "req_7",
        "capability": "flow.step:land/merge",
        "remember": {"flow": "land", "step": "merge", "repository": "/src/app"},
    });
    assert_eq!(
        prompt_for("admin.approvals.resolve", &args, Some(&step)).body,
        "Approve this request and remember the answer. Agents can then run the step \
         \u{201C}merge\u{201D} of the flow \u{201C}land\u{201D} in the repository \
         \u{201C}/src/app\u{201D} without asking you, until you revoke it or the step changes."
    );
}

#[test]
fn network_changes_name_the_proxy_the_bundle_and_never_the_password() {
    let proxy = json!({"proxy": {"url": "http://proxy.corp.example:3128", "auth": "none"}});
    assert_eq!(
        body("admin.network.set", &proxy),
        "Send PAM's connector and download traffic through the proxy \
         \u{201C}http://proxy.corp.example:3128\u{201D}. Whoever runs that proxy sees where PAM \
         connects, and can read the credentials PAM sends to connectors if it inspects TLS."
    );
    let bundle = json!({"ca_bundle": {"path": "/etc/corp/ca.pem"}});
    assert_eq!(
        body("admin.network.set", &bundle),
        "Trust every certificate signed by the CA bundle \u{201C}/etc/corp/ca.pem\u{201D}. \
         Whoever holds that bundle's keys can read the credentials PAM sends to connectors."
    );
    let password = json!({"credential": {"set": "hunter2"}});
    let said = body("admin.network.set", &password);
    assert_eq!(
        said,
        "Save the proxy password you entered. PAM then sends it to the proxy with every request \
         that goes through it."
    );
    let all = json!({
        "proxy": {"url": "http://svc:hunter2@proxy.corp.example:3128/", "auth": "basic"},
        "credential": {"set": "hunter2"},
        "ca_bundle": {"path": "/etc/corp/ca.pem"},
    });
    let said = body("admin.network.set", &all);
    assert!(
        said.starts_with(
            "Send PAM's connector and download traffic through the proxy \
             \u{201C}http://proxy.corp.example:3128/\u{201D}, save the proxy password you \
             entered and trust every certificate signed by the CA bundle"
        ),
        "{said}"
    );
    assert!(said.contains("holds that bundle's keys"), "{said}");
    for case in [&password, &all] {
        assert!(
            !body("admin.network.set", case).contains("hunter2"),
            "a secret is never shown"
        );
    }
}

/// Every args shape the phrase rule guards gets its own sentence, never the generic fallback.
#[test]
fn every_guarded_case_has_its_own_sentence() {
    for (op, args) in [
        ("admin.profile.set", json!({"profile": "relaxed"})),
        ("admin.profile.set", json!({})),
        ("admin.grants.add", json!({"capability": "x"})),
        (
            "admin.approvals.resolve",
            json!({"request_id": "r", "resolution": "approved", "remember": true}),
        ),
        ("admin.network.set", json!({"proxy": {"url": "http://p:1"}})),
        ("admin.network.set", json!({"credential": {"set": "s"}})),
        (
            "admin.network.set",
            json!({"ca_bundle": {"path": "/c.pem"}}),
        ),
    ] {
        assert!(required_confirmation(op, &args).is_some(), "{op} {args}");
        let said = body(op, &args);
        assert!(
            !said.contains("admin."),
            "no op names in the dialog: {said}"
        );
        assert!(!said.starts_with("Make a change"), "{op} {args}: {said}");
    }
}

#[test]
fn quoted_values_cannot_hide_or_fake_text() {
    assert_eq!(shown("fs.write"), "\u{201C}fs.write\u{201D}");
    // A newline cannot start a fake line; bidi overrides and zero-width marks are visible.
    assert_eq!(
        shown("x\nAllow is safe"),
        "\u{201C}x\\u{000A}Allow is safe\u{201D}"
    );
    assert_eq!(
        shown("a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}"),
        "\u{201C}a\\u{202E}b\\u{200B}c\\u{2066}d\\u{FEFF}\u{201D}"
    );
    assert_eq!(shown("p\u{2028}q"), "\u{201C}p\\u{2028}q\u{201D}");
    assert_eq!(shown("tag\u{E0041}"), "\u{201C}tag\\u{E0041}\u{201D}");
    // A long value cannot push the effect out of sight.
    let long = "a".repeat(500);
    let cut = shown(&long);
    assert_eq!(cut.chars().count(), 120 + 3, "{cut}");
    assert!(cut.ends_with("\u{2026}\u{201D}"));
    // Through a sentence too.
    let said = body(
        "admin.grants.add",
        &json!({"capability": "fs.write\nGrant nothing"}),
    );
    assert!(!said.contains('\n'), "{said}");
}

#[test]
fn a_cancel_is_a_legible_refusal() {
    let error = declined("admin.grants.add");
    assert_eq!(error.cause, CAUSE_CONFIRMATION_DECLINED);
    assert_eq!(error.cause, "confirmation_declined");
    assert!(error.detail.contains("nothing changed"), "{}", error.detail);
    assert!(error.recovery.contains(ALLOW_LABEL), "{}", error.recovery);
}

/// The webview never gets the dialog plugin's commands: no capability file grants a `dialog:`
/// permission (strings or `{ identifier }` objects), and the app config enables only capability
/// files by name. Without a grant Tauri refuses every `plugin:dialog|…` invoke, so the plugin is
/// reachable from Rust alone.
#[test]
fn no_capability_grants_the_webview_a_dialog_permission() {
    let app = concat!(env!("CARGO_MANIFEST_DIR"), "/../pam");
    let dir = std::path::Path::new(app).join("capabilities");
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("the capabilities directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(&path).expect("a capability file");
        assert!(!text.contains("dialog:"), "{} names dialog", path.display());
        let capability: Value = serde_json::from_str(&text).expect("capability JSON");
        for permission in capability["permissions"].as_array().expect("permissions") {
            let identifier = permission
                .as_str()
                .or_else(|| permission["identifier"].as_str())
                .expect("a permission identifier");
            assert!(
                !identifier.starts_with("dialog:"),
                "{}: {identifier}",
                path.display()
            );
        }
    }
    assert!(files >= 1, "the main window's capability is read");
    let config: Value = serde_json::from_str(
        &std::fs::read_to_string(std::path::Path::new(app).join("tauri.conf.json"))
            .expect("tauri.conf.json"),
    )
    .expect("config JSON");
    for capability in config["app"]["security"]["capabilities"]
        .as_array()
        .expect("the enabled capabilities")
    {
        assert!(
            capability.is_string(),
            "capabilities are enabled by file name, never inline: {capability}"
        );
    }
    for platform in ["tauri.macos.conf.json", "tauri.windows.conf.json"] {
        let text = std::fs::read_to_string(std::path::Path::new(app).join(platform))
            .expect("platform config");
        assert!(!text.contains("dialog"), "{platform} names dialog");
    }
}
