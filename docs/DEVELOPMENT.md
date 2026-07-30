# Development methodology

How a change gets into this tool. The short version: **an idea is evaluated before it is
built, built by whoever knows that domain, reviewed by someone who did not write it, and
proven on a real machine before it is called done.**

This exists because the expensive bugs in this project were never typos. They were a
multi-gigabyte file overflowing a 32-bit bound, a machine with nobody logged in, a service
holding a file open, and a clock moving mid-collection. None of those are caught by reading
the diff harder. They are caught by asking the right question at the right stage.

---

## The pipeline

```
   REQUEST            EVALUATE           DESIGN            BUILD
   new artifact  ->   is it worth   ->   how, within  ->   implement
   or feature         collecting?        constraints       + mirror OS
                          |                                    |
                          v                                    v
                      may be rejected                       REVIEW
                      or deferred                     independent audit
                                                             |
                                                             v
                                                          VALIDATE
                                                     unit -> VM matrix
                                                             |
                                                             v
                                                          SEAL
                                                   hashes, docs, commit
```

Nothing skips **Evaluate**. Small changes move through the middle stages quickly, but a
change that reaches a target host without ever being questioned is how a collector grows
into a slow, noisy tool that gathers the wrong things.

---

## Stage 1 — Evaluate (before any code)

Every proposed artifact or feature answers these. If the first three have no good answer,
it does not get built.

| Question | Why it decides things |
|---|---|
| **What question does it answer?** | An artifact earns its place by resolving something an investigator actually asks — "what ran", "who logged on", "what left the network". "It might be useful" is not an answer. |
| **Is it obtainable natively?** | No third-party binaries. If it needs a kernel driver or an external tool, it is out of scope — say so plainly rather than shipping something half-working. |
| **Is it already covered?** | Overlap costs collection time and archive size for no new evidence. |
| **What does it cost?** | Size and wall-clock time on the target. Large artifacts belong behind `-Profile full`, not in the default path. |
| **Live-only or on disk?** | Live-only data (open handles, named pipes, in-memory state) is lost on reboot and ranks above anything the disk still holds. |
| **Locked, and by what?** | Decides the acquisition path: direct copy, shadow copy, or raw volume read. |
| **Does the downstream tool understand it?** | A collected artifact with no parser is inert. Either it lands where the parser already looks, or the gap is stated. |
| **What is the OS counterpart?** | The two scripts are mirrors. Decide the Linux equivalent now, or record explicitly that there isn't one. |

Output of this stage: a short written verdict — **build / defer / reject**, with the reason.
A rejection recorded is worth as much as a feature built; it stops the same idea being
re-litigated in three months.

---

## Stage 2 — Design

Constraints are fixed and not up for renegotiation during a feature:

- One self-contained script per OS. No modules, no imports, no install step.
- Native tooling only.
- Output layout and manifest schema stay compatible with the downstream consumer.
- Never abort: whatever was collected still gets sealed.

Decide before writing code: which acquisition path, which profile it belongs to, what
`action` name it uses in the manifest, where it lands in the output tree, and what the
degraded case looks like (because a host without that artifact is normal, not an error).

---

## Stage 3 — Build

Implement on both scripts, or record why only one. Every collection action goes through the
step wrapper so it is hashed and recorded — a copy that bypasses it is invisible to the
chain of custody.

Specialist help is used by domain: PowerShell 5.1 semantics for the Windows side, POSIX
shell portability for the Linux side, forensic soundness for anything touching acquisition
or evidence handling.

---

## Stage 4 — Review

**The reviewer is never the author.** An independent pass looks for: type coercion and
platform-version traps, steps that can throw past the sealing stage, status misclassification
(a normal host state reported as an error), injection through values that came from the
target host, and anything that writes to or alters the source system.

---

## Stage 5 — Validate

Three tiers, cheapest first:

1. **Every edit** — syntax check both scripts; run the unit tests. Seconds.
2. **Every behavioural change** — run against the VM matrix, on a clean reverted guest.
   Assert the run summary, verify both seals, and confirm the artifact is actually present
   and non-empty. A collection that "ran fine" but produced a zero-byte file has failed.
3. **Before a release** — the full matrix across OS versions, elevated and unelevated,
   plus a Linux run.

Environment diversity is not optional here. Every significant bug in this project so far was
found by running on a machine that differed from the developer's.

---

## Stage 6 — Seal

Regenerate the published hashes — a stale hash breaks the allowlist the file exists to
support. Update the contract docs if the output changed. Commit incrementally, describing
the functionality added or improved rather than the files touched.

---

## Working agreements

- **Report faithfully.** If a step degraded, say so with the evidence. A summary that hides
  a failure is worse than no summary.
- **A normal host state is a finding, not an error.** No logged-on user, no firewall, an
  absent registry key — record it in the capture; do not inflate the error count.
- **Evidence never becomes prose.** Values collected from a real host do not go into
  documentation, comments, tests, or commit messages. Synthesise instead.
- **Fix the class, not the instance.** A 32-bit overflow on one bound means auditing every
  bound. A stderr-as-error case means auditing every native call.
