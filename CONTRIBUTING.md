# Contributing

`breadbug-server`: intake, triage and clustering for breadbug reports. Part of
the bread ecosystem; same workflow as the sibling repos.

One long-lived branch, **`main`**. New work goes on `feature/<name>` or
`fix/<name>`, branched from and merged back into `main`. Push to `origin`
(Forgejo); the GitHub mirror syncs on its own.

```sh
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

`tests/fixtures/report_v1.json` is a real report produced by `breadbug
--dry-run`. When the client's report schema changes, regenerate it; the
intake tests parse it, so schema drift fails loudly.

Read `docs/threat-model.md` before touching the public listener: everything
that arrives on it is hostile.
