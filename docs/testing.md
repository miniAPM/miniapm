# Testing

Run the workspace suite with:

```sh
cargo test --workspace
cargo fmt --all -- --check
```

## Conventions

- Keep tests in `<module>/tests.rs`, wired with `#[cfg(test)] mod tests;`.
  Production files should not contain inline test bodies.
- Prefer observable behavior: HTTP responses **and persisted data**, account and
  project lifecycles, retention, aggregation, and tenant isolation.
- Do not add standalone tests for simple formatting, getters, enum mappings,
  token generators, or thin wrappers. Exercise them through their callers.
- Keep focused unit tests for complex logic such as SQL normalization, span
  classification, error-location selection, similarity, timestamp precision,
  validation boundaries, and state-machine transitions. Use tables of cases.
- Use real migrated, isolated in-memory SQLite pools for persistence tests.
  Avoid global environment mutations or external services.
- Assert identities and values rather than only success status or row counts.
  Cover failure paths and repeatable operations where relevant.
- Async tests use `#[tokio::test]`. Returning `anyhow::Result<()>` allows setup
  errors to propagate; use descriptive `expect` messages for required values.
