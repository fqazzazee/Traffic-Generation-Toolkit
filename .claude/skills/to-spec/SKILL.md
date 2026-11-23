---
name: to-spec
description: Turn the current conversation into a spec and publish it as a GitHub issue, with no interview, by synthesizing what has already been discussed.
disable-model-invocation: true
metadata:
  adapted-from: mattpocock/skills@abeeaf9 (MIT, see ../NOTICE.md)
---

# To Spec

Turn the conversation and your understanding of the code into a spec. Do not interview the user. Synthesize what you already know.

## Process

1. Explore the repo if you have not. Read `AGENTS.md`. Use the vocabulary in `GLOSSARY.md` and respect `docs/DECISIONS.md` where they exist.
2. Sketch the test seams. Prefer existing `test_*` groups and the highest seam available: built frames, the manifest, the inventory or a scorecard. Check with the user that the seams match their expectations.
3. Write the spec from the template and show it to the user. Publish it with `gh issue create` once they agree, using the repo's existing `enhancement`, `P*` and `area:*` labels.

## Template

```md
## Problem Statement

The problem from the user's perspective.

## Solution

The solution from the user's perspective.

## User Stories

1. As an <actor>, I want <feature>, so that <benefit>

## Implementation Decisions

Modules to build or change, their interfaces, schema changes, wire-format decisions and architectural choices. No file paths or code snippets, because they go stale. Inline a snippet only when it states a decision more precisely than prose.

## Testing Decisions

What a good test asserts (external behavior only), which modules are tested, and similar existing test groups.

## Out of Scope

What this spec does not cover.

## Further Notes

Anything else an implementer needs.
```
