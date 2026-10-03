//! The native confirmation for the admin ops that widen what agents may do.
//!
//! The webview is a full-admin root: whatever it sends through `admin_call` reaches the daemon's
//! private socket. The in-page typed phrase (`bridge::check_confirmation`) stops misclicks, but a
//! compromised webview can type it too. So for every op `bridge::required_confirmation` names, the
//! bridge itself asks the human in a **native** dialog drawn by the operating system
//! ([`NativeConfirmer`], through Tauri's dialog plugin, from Rust), and sends the op only on an
//! explicit Allow. The dialog's sentence is built here from the op's own arguments — exactly what
//! will be sent — and, for an approval, from the daemon's own record of the pending request
//! ([`prompt_for`]); no text the webview supplies for display ever reaches it.
//!
//! The webview is granted no `dialog:` permission (a test reads the capability files), so it cannot
//! draw a look-alike native dialog of its own either. What this does not stop: a process of the
//! same user that can drive the user interface (accessibility or UI automation) could press Allow
//! itself; the agent sandbox must keep agents away from that, as it keeps them away from the admin
//! socket (`docs/admin-boundary.md`).

use std::fmt::Write as _;
use std::future::Future;

use pam_daemon::admin::{OP_APPROVALS_RESOLVE, OP_GRANTS_ADD, OP_PROFILE_SET};
use pam_daemon::admin_network::OP_NETWORK_SET;
use serde_json::Value;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::bridge::BridgeError;

/// The native dialog's title.
pub const PROMPT_TITLE: &str = "Confirm in PAM";

/// The button that sends the op.
pub const ALLOW_LABEL: &str = "Allow";

/// The button that refuses it.
pub const CANCEL_LABEL: &str = "Cancel";

/// The refusal when the human pressed Cancel (or closed the dialog).
pub const CAUSE_CONFIRMATION_DECLINED: &str = "confirmation_declined";

/// The longest value, in characters, a sentence quotes before it is cut with an ellipsis.
const MAX_SHOWN_CHARS: usize = 120;

/// What the native dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    /// Always [`PROMPT_TITLE`].
    pub title: &'static str,
    /// One or two plain sentences naming the effect.
    pub body: String,
}

impl Prompt {
    fn new(body: String) -> Self {
        Self {
            title: PROMPT_TITLE,
            body,
        }
    }
}

/// Asks the human. True only on an explicit Allow.
pub trait Confirmer: Send + Sync {
    /// Shows `prompt` and answers whether the human allowed it. Anything that is not an explicit
    /// Allow — Cancel, a closed dialog, a dialog that could not be shown — is false.
    fn confirm(&self, prompt: &Prompt) -> impl Future<Output = bool> + Send;
}

/// The real dialog: Tauri's dialog plugin, called from Rust, modal to the main window.
///
/// It cannot be clicked in CI; the bridge tests drive the same path with a fake [`Confirmer`].
pub struct NativeConfirmer<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> NativeConfirmer<R> {
    /// A confirmer for this app.
    #[must_use]
    pub const fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> Confirmer for NativeConfirmer<R> {
    async fn confirm(&self, prompt: &Prompt) -> bool {
        let (answer, answered) = tokio::sync::oneshot::channel();
        let mut dialog = self
            .app
            .dialog()
            .message(prompt.body.clone())
            .title(prompt.title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                ALLOW_LABEL.to_owned(),
                CANCEL_LABEL.to_owned(),
            ));
        // Modal to the window, so it cannot fall behind it (a sheet on macOS).
        if let Some(window) = self.app.get_webview_window("main") {
            dialog = dialog.parent(&window);
        }
        dialog.show(move |allowed| {
            // The receiver is gone only if the command was dropped; nothing is sent then.
            let _ = answer.send(allowed);
        });
        // A dialog the plugin could not show drops the sender unanswered: that is a refusal.
        answered.await.unwrap_or(false)
    }
}

/// The refusal for a Cancel.
#[must_use]
pub fn declined(op: &str) -> BridgeError {
    BridgeError::new(
        CAUSE_CONFIRMATION_DECLINED,
        format!("you cancelled {op} in PAM's confirmation dialog; nothing changed"),
        "Try again and choose Allow in the dialog if you meant it.",
    )
}

/// The dialog for `op` with `args`, for an op `bridge::required_confirmation` guards. `pending` is
/// the daemon's own entry for the request an `admin.approvals.resolve` names (from
/// `admin.approvals.pending`), when the daemon answered with one.
///
/// Every value quoted comes from the arguments that will be sent, shown with hidden characters
/// escaped and cut at a fixed length ([`shown`]); a password is never quoted.
#[must_use]
pub fn prompt_for(op: &str, args: &Value, pending: Option<&Value>) -> Prompt {
    Prompt::new(match op {
        OP_PROFILE_SET => profile_sentence(args),
        OP_GRANTS_ADD => grant_sentence(args),
        OP_APPROVALS_RESOLVE => remember_sentence(args, pending),
        OP_NETWORK_SET => network_sentence(args),
        // Not guarded today; a new guarded op without its own sentence still asks, plainly.
        _ => format!(
            "Make a change that widens what agents may do ({}).",
            shown(op)
        ),
    })
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

fn profile_sentence(args: &Value) -> String {
    match str_arg(args, "profile") {
        Some("relaxed") => "Relax the security profile to relaxed. Safe capabilities will then \
                            grant themselves the first time an agent uses them, without asking you."
            .to_owned(),
        Some(other) => format!(
            "Change the security profile to {}. PAM does not know this profile; it may widen \
             what agents can do without asking you.",
            shown(other)
        ),
        None => "Change the security profile to one PAM cannot read. It may widen what agents \
                 can do without asking you."
            .to_owned(),
    }
}

fn grant_sentence(args: &Value) -> String {
    let capability = str_arg(args, "capability").map_or_else(|| "a capability".to_owned(), shown);
    let reach = match str_arg(args, "repository") {
        Some(repository) => format!("in the repository {}", shown(repository)),
        None => "in every repository".to_owned(),
    };
    format!(
        "Grant {capability} to every agent {reach}. Agents can then use it without asking you, \
         until you revoke it in Settings."
    )
}

fn remember_sentence(args: &Value, pending: Option<&Value>) -> String {
    let Some(entry) = pending else {
        let request = str_arg(args, "request_id").map_or_else(|| "a request".to_owned(), shown);
        return format!(
            "Approve {request} and remember the answer. Agents can then use what it asked for \
             again without asking you, until you revoke it in Settings."
        );
    };
    let capability = str_arg(entry, "capability").map_or_else(|| "it".to_owned(), shown);
    match entry.get("remember").filter(|scope| scope.is_object()) {
        Some(scope) => {
            let step = match (str_arg(scope, "flow"), str_arg(scope, "step")) {
                (Some(flow), Some(step)) => {
                    format!("the step {} of the flow {}", shown(step), shown(flow))
                }
                _ => capability,
            };
            let reach = match str_arg(scope, "repository") {
                Some(repository) => format!("in the repository {}", shown(repository)),
                None => "in every repository".to_owned(),
            };
            format!(
                "Approve this request and remember the answer. Agents can then run {step} {reach} \
                 without asking you, until you revoke it or the step changes."
            )
        }
        None => format!(
            "Approve this request and remember the answer. Every agent in every repository can \
             then use {capability} without asking you, until you revoke it in Settings."
        ),
    }
}

fn network_sentence(args: &Value) -> String {
    let sets = |key: &str| {
        args.get(key)
            .filter(|value| !value.is_null() && value.get("clear").is_none())
    };
    let mut parts = Vec::new();
    if let Some(proxy) = sets("proxy") {
        let at = str_arg(proxy, "url").map_or_else(
            || "a proxy".to_owned(),
            |url| format!("the proxy {}", shown(&without_userinfo(url))),
        );
        parts.push(format!(
            "send PAM's connector and download traffic through {at}"
        ));
    }
    if sets("credential").is_some() {
        parts.push("save the proxy password you entered".to_owned());
    }
    if let Some(bundle) = sets("ca_bundle") {
        let from = str_arg(bundle, "path").map_or_else(
            || "a CA bundle".to_owned(),
            |path| format!("the CA bundle {}", shown(path)),
        );
        parts.push(format!("trust every certificate signed by {from}"));
    }
    let what = match parts.as_slice() {
        [] => "change how PAM reaches the network".to_owned(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    let reach = match (sets("proxy").is_some(), sets("ca_bundle").is_some()) {
        (true, true) => {
            "Whoever runs that proxy or holds that bundle's keys can read the credentials PAM \
             sends to connectors."
        }
        (true, false) => {
            "Whoever runs that proxy sees where PAM connects, and can read the credentials PAM \
             sends to connectors if it inspects TLS."
        }
        (false, true) => {
            "Whoever holds that bundle's keys can read the credentials PAM sends to connectors."
        }
        (false, false) => "PAM then sends it to the proxy with every request that goes through it.",
    };
    format!("{}. {reach}", capitalized(&what))
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// A proxy URL with any `user:password@` cut out of its authority: the dialog never shows a secret.
fn without_userinfo(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if scheme.is_empty() {
        format!("{host}{path}")
    } else {
        format!("{scheme}://{host}{path}")
    }
}

/// `value` as a sentence quotes it: in quotes, every hidden character (controls, format characters
/// such as bidi overrides and zero-width marks, the line and paragraph separators) shown as a
/// `\u{…}` escape — the same set the frontend's `SafeText` escapes — and cut at
/// `MAX_SHOWN_CHARS` characters with an ellipsis, so a value cannot fake a line of the dialog or
/// push its real effect out of sight.
#[must_use]
pub fn shown(value: &str) -> String {
    let mut out = String::from("\u{201C}");
    for (index, ch) in value.chars().enumerate() {
        if index == MAX_SHOWN_CHARS {
            out.push('\u{2026}');
            break;
        }
        if is_hidden(ch) {
            let _ = write!(out, "\\u{{{:04X}}}", u32::from(ch));
        } else {
            out.push(ch);
        }
    }
    out.push('\u{201D}');
    out
}

/// Controls, format characters (Unicode category Cf) and the line/paragraph separators.
fn is_hidden(ch: char) -> bool {
    ch.is_control()
        || matches!(
            u32::from(ch),
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
}
