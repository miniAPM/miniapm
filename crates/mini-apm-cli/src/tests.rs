use super::*;

fn parse(args: &[&str]) -> Result<(String, Vec<Option<String>>), cli::Exit> {
    let argv: Vec<String> = std::iter::once("miniapm-cli")
        .chain(args.iter().copied())
        .map(String::from)
        .collect();
    let out = cli::parse(USAGE, &argv)?;
    let values = ["project", "username", "password"]
        .map(|n| cli::value(&out, n).map(String::from))
        .to_vec();
    Ok((out.cmd.name.clone(), values))
}

#[test]
fn test_commands_parse() {
    let some = |s: &str| Some(s.to_string());
    for (args, cmd, values) in [
        (
            &["regenerate-key", "default"][..],
            "regenerate-key",
            [some("default"), None, None],
        ),
        (&["list-projects"][..], "list-projects", [None, None, None]),
        (
            &["reset-password", "bob", "hunter2"][..],
            "reset-password",
            [None, some("bob"), some("hunter2")],
        ),
        (&["list-users"][..], "list-users", [None, None, None]),
    ] {
        let (got_cmd, got_values) = parse(args).unwrap();
        assert_eq!(
            (got_cmd.as_str(), got_values),
            (cmd, values.to_vec()),
            "{args:?}"
        );
    }
}

#[test]
fn test_help_and_errors_exit() {
    for (args, code) in [
        (&["--help"][..], 0),
        (&["--version"][..], 0),
        (&[][..], 2),
        (&["regenerate-key"][..], 2),
        (&["bogus"][..], 2),
    ] {
        assert_eq!(parse(args).unwrap_err().code, code, "{args:?}");
    }
}
