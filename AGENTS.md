# Repository guidance

For error handling, API diagnostics, and CLI failure paths, follow
[docs/error-reporting.md](docs/error-reporting.md). Preserve typed causes,
provide actionable help, and report partial completion accurately.

Run `python3 -m unittest discover -s cli/tests -v` for Python CLI changes.
Use `cargo nextest run` rather than `cargo test` for Rust tests, as described in
[CONTRIBUTING.md](CONTRIBUTING.md).
