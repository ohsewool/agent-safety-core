"""Execution safety core.

This file exists to make `core` a regular package rather than a namespace one,
which is a security property here rather than a style preference.

Shipped without it, `core` was a namespace package, and namespace portions
merge: a directory named `core` in the working directory joined the same
package and came first, so `core.ledger` resolved to the user's file instead of
this one. Measured, not assumed - a `core/ledger.py` holding an
`ExecutionLedger` whose `approve` returned unconditionally was imported in
preference to this one, by a library whose entire purpose is that approvals are
enforced.

With `__init__.py` present this becomes a regular package, and the import
system stops at the first regular package on the path rather than merging
portions. `adapters` and `profiles` already had one; `core` did not, and a first pass at
this reported all three as namespace packages because the script checking them
was wrong. All three carry one now, and `docs/PACKAGING.md` records the
collision that remains.
"""
