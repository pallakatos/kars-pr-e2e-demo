# Connect-GitHub Flow Proof

**Date:** 2026-07-07

This pull request was created by a mission wired **entirely through the
Bridge's GitHub connection**.

- No `kubectl` secret was mounted or read.
- The agent held **no GitHub credential** of its own.
- Git write access was brokered by the workspace's GitHub connection; the
  controller materialized the required scope just-in-time.
- The PR was opened via the inference-router's `/gh-api` proxy, which
  attaches the connection-derived token server-side.

This file's presence in the branch `kars/connect-flow` is the artifact
proving the keyless Connect-GitHub flow end to end.
