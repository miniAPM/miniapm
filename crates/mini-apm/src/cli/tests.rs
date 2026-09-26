use super::*;

const COLLECTOR: &str = include_str!("../bin/server/miniapm.usage.kdl");

fn parse_collector(args: &[&str]) -> Result<ParseOutput, Exit> {
    let argv: Vec<String> = std::iter::once("miniapm")
        .chain(args.iter().copied())
        .map(String::from)
        .collect();
    parse(COLLECTOR, &argv)
}

#[test]
fn test_port_flag_and_default() {
    for (args, port) in [
        (&[][..], "3000"),
        (&["-p", "8080"][..], "8080"),
        (&["--port", "9"][..], "9"),
    ] {
        let out = parse_collector(args).unwrap();
        assert_eq!(value(&out, "port"), Some(port), "{args:?}");
    }
}

#[test]
fn test_help_version_and_errors() {
    let help = parse_collector(&["--help"]).unwrap_err();
    assert_eq!(help.code, 0);
    assert!(help.message.contains("MiniAPM Server"), "{}", help.message);

    let version = parse_collector(&["--version"]).unwrap_err();
    assert_eq!(
        (version.code, version.message.as_str()),
        (0, env!("CARGO_PKG_VERSION"))
    );

    for args in [&["--bogus"][..], &["-p"][..]] {
        assert_eq!(parse_collector(args).unwrap_err().code, 2, "{args:?}");
    }
}
