# Governance

## Project Structure

Provara is a single-maintainer open-source project. We believe in being transparent about how decisions are made and how the project is run.

## Decision-Making

The Provara maintainer has final authority on all project decisions, including:

- Feature direction and roadmap priorities
- Pull request acceptance or rejection
- Release timing and versioning
- Dependency changes
- Protocol specification amendments

Community input is welcomed and encouraged through GitHub Issues and Discussions. We read and consider all feedback, and good ideas regularly shape the project's direction. However, this is not a committee-driven project -- decisions are made by the maintainer to keep momentum high and direction consistent.

## Protocol Specification

The protocol specification (`PROTOCOL_PROFILE.txt`) is **frozen**. It defines the normative behavior that all implementations must conform to. Changes to the frozen spec require a formal RFC process:

1. Open a GitHub Issue describing the proposed change and its motivation.
2. The Provara team evaluates the proposal against backward compatibility, security implications, and protocol simplicity.
3. If accepted for consideration, the proposal is drafted as a numbered RFC in the repository.
4. A review period (minimum 30 days) allows community comment.
5. The maintainer makes the final accept/reject decision with a written rationale.

Implementations may add non-normative extensions as long as they do not violate the frozen spec.

## Contributions

Contributions are welcome via pull request. All contributions are governed by the guidelines in [CONTRIBUTING.md](CONTRIBUTING.md). By submitting a pull request, you agree that your contribution is licensed under Apache 2.0, consistent with the project license.

## Bus Factor and Continuity

We are honest about the risk: this is a single-maintainer project. If the maintainer becomes unavailable:

- **The code is Apache 2.0.** Anyone can fork, modify, and distribute the project without permission from the original maintainer.
- **Key escrow and succession planning are in progress.** We are working on a plan to ensure continuity of signing keys and project credentials.
- **The protocol spec is public and frozen.** A new maintainer or fork can implement the protocol from the specification alone, without access to this particular codebase.

We take this risk seriously and are actively working to reduce it. If you are interested in becoming a co-maintainer as the project grows, reach out via GitHub Issues.

## Versioning

Provara follows [Semantic Versioning](https://semver.org/):

- **Patch releases (0.1.x):** Bug fixes, documentation updates, non-breaking changes.
- **Minor releases (0.x.0):** New features, new tools, backward-compatible additions.
- **Major releases (x.0.0):** Breaking changes to the MCP tool interface or vault format.

During the 0.x phase, minor releases may include breaking changes with advance notice.

## Contact

For governance questions, open a GitHub Issue or email **hello@provara.dev**.
