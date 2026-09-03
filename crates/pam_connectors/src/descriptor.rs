//! What each connector is: its display name, how it authenticates, whether
//! it needs a base URL, and the calls a flow may make.
//!
//! The call table is not written here. It lives in `pam_flow`, because the
//! flow validator refuses a step whose call or arguments are unknown, and
//! two copies of that table would eventually disagree. [`Descriptor::calls`]
//! is the very same slice [`pam_flow::connector_calls`] returns.

use std::sync::LazyLock;

use pam_flow::{CallSpec, ConnectorId, connector_calls};

/// How a connector proves who pam is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// `Authorization: Bearer <secret>` — GitHub, Jira, `SharePoint`.
    Bearer,
    /// `Authorization: Basic base64(username:secret)` — Jenkins (a user
    /// name) and Confluence (an account email).
    BasicUserSecret,
    /// `Authorization: Basic base64(secret:)` — `SonarQube` puts the token
    /// where the user name goes and leaves the password empty.
    TokenAsUser,
    /// No credential at all: the local `aws` CLI resolves `~/.aws` itself,
    /// and the row's user name is the optional profile.
    AwsProfile,
}

/// One connector, described for the GUI and for the call dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// Which connector this describes.
    pub id: ConnectorId,
    /// The name a human reads, in the vendor's own spelling.
    pub name: &'static str,
    /// How pam authenticates to it.
    pub auth: AuthKind,
    /// Whether the row must carry a base URL before the connector works.
    pub needs_base_url: bool,
    /// What the row's `username` column means here, when it means anything.
    pub username_label: Option<&'static str>,
    /// The read-only calls a flow step may name.
    pub calls: &'static [CallSpec],
}

/// The seven descriptors, in [`ConnectorId::ALL`] order.
///
/// Lazy rather than `static`, only because [`connector_calls`] is a plain
/// function: the table it returns is itself `'static`, so nothing is copied.
static DESCRIPTORS: LazyLock<[Descriptor; 7]> = LazyLock::new(|| ConnectorId::ALL.map(build));

/// Everything pam knows about one connector.
#[must_use]
pub fn descriptor(id: ConnectorId) -> &'static Descriptor {
    &DESCRIPTORS[index_of(id)]
}

/// Every descriptor, in the order the GUI lists connectors.
#[must_use]
pub fn descriptors() -> &'static [Descriptor; 7] {
    &DESCRIPTORS
}

/// Where a connector sits in [`ConnectorId::ALL`].
fn index_of(id: ConnectorId) -> usize {
    match id {
        ConnectorId::Github => 0,
        ConnectorId::Jenkins => 1,
        ConnectorId::Sonarqube => 2,
        ConnectorId::Jira => 3,
        ConnectorId::Confluence => 4,
        ConnectorId::Sharepoint => 5,
        ConnectorId::Aws => 6,
    }
}

/// The one place a connector's shape is written down.
fn build(id: ConnectorId) -> Descriptor {
    let (name, auth, needs_base_url, username_label) = match id {
        ConnectorId::Github => ("GitHub", AuthKind::Bearer, true, None),
        ConnectorId::Jenkins => ("Jenkins", AuthKind::BasicUserSecret, true, Some("user")),
        ConnectorId::Sonarqube => ("SonarQube", AuthKind::TokenAsUser, true, None),
        ConnectorId::Jira => ("Jira", AuthKind::Bearer, true, None),
        ConnectorId::Confluence => ("Confluence", AuthKind::BasicUserSecret, true, Some("email")),
        ConnectorId::Sharepoint => ("SharePoint", AuthKind::Bearer, true, None),
        ConnectorId::Aws => ("AWS", AuthKind::AwsProfile, false, Some("profile")),
    };
    Descriptor {
        id,
        name,
        auth,
        needs_base_url,
        username_label,
        calls: connector_calls(id),
    }
}
