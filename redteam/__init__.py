"""Week 17 attack harness for CodeGuardian.

The harness replays saved attack payloads against two designs of the reviewer:

- hardened: the shipped CodeGuardian code, run unmodified;
- naive: the same pipeline with every control replaced by the version a team might write
  without them.

Ablation modes start from hardened and remove named controls. The shipped package has no
vulnerable mode; every replacement lives in this harness.
"""
