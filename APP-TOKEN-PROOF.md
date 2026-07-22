# GitHub App Keyless PR Proof

**Date:** 2026-07-07

This pull request was opened via a **scoped GitHub App installation token**
that was injected by the kars inference/egress router at request time.

The agent itself held **no GitHub credential** at any point:

- No personal access token (PAT) was present in the environment.
- No SSH key or OAuth token was visible to the agent.
- The router transparently attached a short-lived, repository-scoped
  GitHub App installation token to the outbound `git push` and to the
  GitHub REST API call that created this PR.

In other words: **keyless, least-privilege, agent-never-saw-the-secret.**
