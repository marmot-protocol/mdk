Guidelines for code that is small, clear and easy to
change. They complement karpathy-guidelines.md, which
covers how to work; these cover what the code should
look like. Project instructions win where they differ.

## 1. Simple Design
In priority order, the code:
1. Passes the tests.
2. Says what it does. Names carry the intent.
3. Says each thing once.
4. Has nothing else: no element without a job.

When two rules pull apart, the earlier one wins.

## 2. Deletion Is Progress
The best change is often a smaller codebase.

- Count a net-negative diff as a win, not a side effect.
- Remove what your change made dead, in the same change:
  callers, helpers, flags, config, tests, docs.
- Before deleting something that looks pointless, find out
  why it exists (`git log -S`, the PR that added it). Delete
  it once you know, not before.
- Do not leave commented-out code or "just in case" paths.
  Version control remembers.

## 3. Duplication vs. the Wrong Abstraction
Reuse first, abstract late.

- Search before you write. If the codebase already has a
  helper, type or pattern for this, use it.
- Two similar blocks are not yet a pattern. Wait for the
  third before extracting, and extract only what is truly
  the same.
- A wrong abstraction costs more than duplication. If a
  shared helper needs flags or branches for each caller,
  inline it back into the callers and start over.

## 4. Deep, Not Wide
A module earns its place by hiding more than it exposes.

- Prefer a small interface over a lot of behavior to many
  thin layers that each do a little.
- No pass-through wrappers, managers or adapters that only
  forward calls. Call the real thing.
- Keep details inside the module that owns them. If callers
  must know an internal format or ordering, the boundary is
  in the wrong place.
- Handle errors where the code can act on them. Don't catch
  and rethrow, or check for states that cannot happen.

## 5. Let Types Hold the Rules
If a state is invalid, make it impossible to build.

- Model data so invalid combinations cannot exist: an enum
  or sum type over a pile of booleans and optional fields,
  a type per state over one struct with a `status` field.
- Parse, don't validate. Turn raw input into a precise type
  once, at the boundary, and pass that type inward. Code
  past the boundary trusts it and does not check again.
- A check that returns nothing teaches the compiler nothing.
  Prefer a constructor that returns the valid type or an
  error over a function that only says "ok".
- Use distinct types for values that are easy to mix up:
  ids of different things, units, raw vs. escaped strings.

## 6. Clear Over Clever
Code is read far more often than it is written.

- Choose the obvious construct over the compact one.
- Name things for what they mean to the caller, not how
  they work.
- Comments say why, not what. If code needs a comment to
  say what it does, rename or restructure it first.
- Keep related code together, and the happy path at the
  lowest indentation.

## 7. One Kind of Change at a Time
Reviewers can trust what they can follow.

- Keep structural changes (renames, moves, extractions)
  apart from behavior changes: separate commits at least,
  separate PRs when either is large.
- A refactor should not change any test's outcome. A
  behavior change should come with the test that shows it.
