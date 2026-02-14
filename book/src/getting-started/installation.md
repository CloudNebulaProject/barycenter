# Installation

Barycenter can be installed by building from source or by running the pre-built Docker image. Choose the method that best fits your environment.

## Installation Methods

- **[Prerequisites](./prerequisites.md)** -- Required and optional tooling for building and running Barycenter.
- **[Building from Source](./building-from-source.md)** -- Clone the repository, compile with Cargo, and locate the output binary.
- **[Docker](./docker.md)** -- Pull the container image or build it locally, with guidance on port mapping and volume mounts.

## Which Method to Choose

| Method | Best for | Requirements |
|--------|----------|--------------|
| Build from source | Development, customization, contribution | Rust toolchain, SQLite or PostgreSQL dev libs |
| Docker | Quick evaluation, CI/CD, production deployment | Docker or compatible container runtime |

After installation, proceed to the [Quickstart](./quickstart.md) guide to run Barycenter and issue your first tokens.
