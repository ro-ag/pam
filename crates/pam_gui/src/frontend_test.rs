use std::ffi::OsStr;

use crate::frontend::{DEV_SWITCH, DEV_URL, DevFrontendRefused, Frontend, choose};

#[test]
fn a_build_without_the_embedded_frontend_refuses_unless_asked() {
    let error = choose(true, None).expect_err("no switch, no development frontend");
    assert_eq!(error, DevFrontendRefused);
    let text = error.to_string();
    assert!(text.contains(DEV_SWITCH), "names the switch: {text}");
    assert!(text.contains(DEV_URL), "names what would be loaded: {text}");
    assert!(
        text.contains("gui:build"),
        "names the release way out: {text}"
    );
}

#[test]
fn only_the_exact_value_opts_in() {
    for value in ["", "0", "true", "yes", "1 ", " 1", "11", "on"] {
        assert_eq!(
            choose(true, Some(OsStr::new(value))),
            Err(DevFrontendRefused),
            "{value:?} is not the switch"
        );
    }
    assert_eq!(
        choose(true, Some(OsStr::new("1"))),
        Ok(Frontend::Development)
    );
}

#[test]
fn a_release_build_never_reads_the_switch() {
    assert_eq!(choose(false, None), Ok(Frontend::Embedded));
    assert_eq!(
        choose(false, Some(OsStr::new("1"))),
        Ok(Frontend::Embedded),
        "the switch changes nothing in an embedded build"
    );
}
