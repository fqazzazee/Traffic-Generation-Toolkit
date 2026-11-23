# AGENTS.md — TGT

TGT generates OT/ICS and IT traffic onto veth, AF_PACKET or pcap so passive network monitors
can be evaluated against known ground truth.

## Hard rules

- **Standard library only, Python 3.9+.** No scapy, no pip dependencies. Frames are built
  byte by byte.
- **No exploit builders.** Attack scenarios model what a monitor should see on the wire. They
  never carry working exploit payloads.
- **Stay vendor-neutral.** Scoring, benches and scorecards use generic or bring-your-own maps.
  Add a product-named map, doc or feature only when the maintainer asks for that product.
- **Simulated traffic stays simulated.** Never add code that connects to a real vendor service,
  or that carries real credentials, customer IDs or tenant identifiers.

## Working in the code

- Every build site must hold `protocols.BUILD_LOCK`, because injection passes build on a worker
  thread.
- Never compute a port as `_sport() + N`.
- `incidents.map_onto` must never map both ends of a flow onto one host.
- Tests that encode built-in environment conventions must filter on `enterprise.BUILTIN_KEYS`,
  because packaged sites may or may not be loaded.
- Reference detail belongs in `docs/`. The README stays a short overview.

## Testing

- Full suite: `python3 tests/selftest.py` (about a minute). Groups are `test_*` functions in
  `tests/selftest.py`, and they run alphabetically.
- When generating a pcap, pass `--rate 0`. The default 20 pps makes `--once` take minutes.
- With tshark installed, `tshark -r x.pcap -q -z expert` should warn only on deliberate RSTs.
- Plain AF_PACKET may fail with EPERM in a sandbox. `unshare -rn` gives a netns where veth and
  AF_PACKET work.

## Commits and releases

- One concern per commit. Do not add co-author trailers.
- Work lands through a PR, and the maintainer merges it.
- A release updates `tgt/__init__.py` and moves the `CHANGELOG.md` Unreleased section under the
  new version. The changelog section becomes the GitHub release notes.

## Skill notes

Shared engineering skills live in `~/.claude/skills`. `to-spec` and `implement` are in
`.claude/skills`.

- **Issue tracker:** GitHub Issues on this repo, using `gh`. Use the existing labels (`P0`–`P2`,
  `area:*`, `bug`, `enhancement`). Do not invent a label scheme.
- **tdd:** the test seam is a `test_*` group in `tests/selftest.py`. Prefer asserting on built
  frames, the manifest or the inventory over internal helpers.
- **diagnosing-bugs:** reproduce with a seeded pcap build before changing code. Live tests run
  in a veth netns or on the lab machine, never on a production network.
- **domain-modeling:** terms go in `GLOSSARY.md`, decisions in `docs/DECISIONS.md`. Create them
  when the first term or decision is settled.
