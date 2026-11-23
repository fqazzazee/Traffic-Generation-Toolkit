---
name: implement
description: Implement a piece of work from a spec or tickets, test-first, ending with a code review and a commit on the current branch.
disable-model-invocation: true
metadata:
  adapted-from: mattpocock/skills@abeeaf9 (MIT, see ../NOTICE.md)
---

# Implement

Implement the work the user describes in the spec or tickets.

If the user passes a ticket reference, fetch it with `gh issue view` and state its title before starting. If the reference is ambiguous, ask.

1. Read `AGENTS.md` and follow its hard rules.
2. Call the Skill tool with "tdd" where possible, using `test_*` groups in `tests/selftest.py` as the seam.
3. Run the groups you touched regularly. Run the full suite with `python3 tests/selftest.py` once at the end.
4. Call the Skill tool with "code-review" to review the work, and fix what it confirms.
5. Commit to the current branch, one concern per commit, with no co-author trailer.
