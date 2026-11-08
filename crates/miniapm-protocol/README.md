# miniapm-protocol

Wire types for the [MiniAPM](https://github.com/miniapm/miniapm) ingest API: errors, error
batches and deploys, plus the paths they post to. The MiniAPM collector deserializes these
same types, so a client built on them stays in step with the server.

```rust
use miniapm_protocol::{ERRORS_PATH, IncomingError};

let error = IncomingError {
    exception_class: "RuntimeError".into(),
    message: "boom".into(),
    backtrace: vec!["app/models/user.rb:42:in `validate'".into()],
    fingerprint: "RuntimeError:app/models/user.rb:42".into(),
    request_id: None,
    user_id: None,
    params: None,
    timestamp: None,
    source_context: None,
};
// POST {base}{ERRORS_PATH} with `Authorization: Bearer <project api key>`
let body = serde_json::to_vec(&error)?;
```

Traces go to `TRACES_PATH` as standard OTLP; this crate does not redefine them.
