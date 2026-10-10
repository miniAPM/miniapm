//! Command-line parsing from usage specs (<https://usage.jdx.dev>)

use usage::parse::{ParseOutput, ParseValue};
use usage::{Parser, Spec};

#[cfg(test)]
mod tests;

/// Why parsing stopped short of a command to run
#[derive(Debug)]
pub struct Exit {
    pub code: i32,
    pub message: String,
}

impl Exit {
    /// Print the message (stdout on success, stderr otherwise) and exit
    pub fn exit(self) -> ! {
        if self.code == 0 {
            println!("{}", self.message);
        } else {
            eprintln!("{}", self.message);
        }
        std::process::exit(self.code)
    }
}

/// Parse `args` (argv[0] included) against a KDL usage spec. Help and
/// version requests come back as a successful [`Exit`], usage errors as
/// exit code 2.
pub fn parse(spec: &str, args: &[String]) -> Result<ParseOutput, Exit> {
    let mut spec: Spec = spec.parse().expect("embedded usage spec is valid");
    spec.version = Some(env!("CARGO_PKG_VERSION").to_string());

    let usage_error = |message: String| Exit { code: 2, message };
    let out = Parser::new(&spec)
        .explain(args)
        .map_err(|e| usage_error(e.to_string()))?;

    if let Some(usage::error::UsageErr::Help(text) | usage::error::UsageErr::Version(text)) =
        out.errors.first()
    {
        return Err(Exit {
            code: 0,
            message: text.clone(),
        });
    }
    if !out.errors.is_empty() {
        let errors: Vec<String> = out.errors.iter().map(ToString::to_string).collect();
        return Err(usage_error(errors.join("\n")));
    }
    Ok(out)
}

/// Parse the process arguments, exiting on help, version or usage errors
pub fn parse_env(spec: &str) -> ParseOutput {
    let args: Vec<String> = std::env::args().collect();
    parse(spec, &args).unwrap_or_else(|exit| exit.exit())
}

/// The value of the argument or flag called `name`, given or defaulted
pub fn value<'a>(out: &'a ParseOutput, name: &str) -> Option<&'a str> {
    let args = out.args.iter().map(|(arg, v)| (&arg.name, v));
    let flags = out.flags.iter().map(|(flag, v)| (&flag.name, v));
    args.chain(flags)
        .find(|(n, _)| *n == name)
        .and_then(|(_, v)| match v {
            ParseValue::String(s) => Some(s.as_str()),
            _ => None,
        })
}
