use super::*;

#[test]
fn defaults_only_when_unset() {
    assert_eq!(parse(Err(VarError::NotPresent)).unwrap(), 3001);
    for value in ["", "invalid", "65536"] {
        let error = parse(Ok(value.into())).unwrap_err();
        assert!(error.to_string().contains("ADMIN_PORT"), "{error}");
    }
}

#[test]
fn explicit_values_override_the_default_including_ephemeral_ports() {
    for (value, expected) in [("4312", 4312), ("0", 0)] {
        assert_eq!(parse(Ok(value.into())).unwrap(), expected);
    }
}

#[cfg(unix)]
#[test]
fn non_unicode_values_do_not_fall_back_to_the_default() {
    use std::os::unix::ffi::OsStringExt as _;
    let value = std::ffi::OsString::from_vec(vec![0xff]);
    let error = parse(Err(VarError::NotUnicode(value))).unwrap_err();
    assert_eq!(error.to_string(), "ADMIN_PORT must contain valid UTF-8");
}
