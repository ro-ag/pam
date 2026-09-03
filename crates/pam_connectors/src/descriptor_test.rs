use std::ptr;

use pam_flow::{ConnectorId, connector_calls};

use crate::{AuthKind, descriptor, descriptors};

#[test]
fn the_call_table_is_pam_flows_own_slice() {
    for id in ConnectorId::ALL {
        let ours = descriptor(id).calls;
        let theirs = connector_calls(id);
        assert!(
            ptr::eq(ours, theirs),
            "{id} keeps a second copy of the call table"
        );
    }
}

#[test]
fn every_descriptor_describes_itself() {
    for id in ConnectorId::ALL {
        assert_eq!(descriptor(id).id, id);
        assert!(!descriptor(id).name.is_empty());
    }
    let listed: Vec<ConnectorId> = descriptors().iter().map(|entry| entry.id).collect();
    assert_eq!(listed, ConnectorId::ALL.to_vec());
}

#[test]
fn names_are_spelled_the_way_the_vendors_spell_them() {
    let names: Vec<&str> = descriptors().iter().map(|entry| entry.name).collect();
    assert_eq!(
        names,
        vec![
            "GitHub",
            "Jenkins",
            "SonarQube",
            "Jira",
            "Confluence",
            "SharePoint",
            "AWS"
        ]
    );
}

#[test]
fn auth_kinds_follow_the_spec_table() {
    assert_eq!(descriptor(ConnectorId::Github).auth, AuthKind::Bearer);
    assert_eq!(descriptor(ConnectorId::Jira).auth, AuthKind::Bearer);
    assert_eq!(descriptor(ConnectorId::Sharepoint).auth, AuthKind::Bearer);
    assert_eq!(
        descriptor(ConnectorId::Jenkins).auth,
        AuthKind::BasicUserSecret
    );
    assert_eq!(
        descriptor(ConnectorId::Confluence).auth,
        AuthKind::BasicUserSecret
    );
    assert_eq!(
        descriptor(ConnectorId::Sonarqube).auth,
        AuthKind::TokenAsUser
    );
    assert_eq!(descriptor(ConnectorId::Aws).auth, AuthKind::AwsProfile);
}

#[test]
fn only_aws_needs_no_base_url() {
    for id in ConnectorId::ALL {
        assert_eq!(
            descriptor(id).needs_base_url,
            id != ConnectorId::Aws,
            "{id}"
        );
    }
}

#[test]
fn the_username_column_is_labelled_where_it_means_something() {
    assert_eq!(
        descriptor(ConnectorId::Jenkins).username_label,
        Some("user")
    );
    assert_eq!(
        descriptor(ConnectorId::Confluence).username_label,
        Some("email")
    );
    assert_eq!(descriptor(ConnectorId::Aws).username_label, Some("profile"));
    for id in [
        ConnectorId::Github,
        ConnectorId::Sonarqube,
        ConnectorId::Jira,
        ConnectorId::Sharepoint,
    ] {
        assert_eq!(descriptor(id).username_label, None, "{id}");
    }
}

#[test]
fn the_dispatcher_answers_every_call_the_table_offers() {
    // Not a call here: `crate::call` matches on the same names, so a call
    // in the table with no arm would be an unknown_call refusal at run time.
    for id in ConnectorId::ALL {
        assert!(!descriptor(id).calls.is_empty(), "{id} offers nothing");
    }
}
