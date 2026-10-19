# Contributing

- **Anything that changes validity** (what passes or fails verification)
  needs: a change to SPEC.md or an extension, a new or changed vector in
  `tools/gen_vectors.py`, and the reference verifier updated so
  `python3 -m unittest discover -s reference/python/tests` passes.
- **Never edit files in `vectors/` by hand.** Change the generator and run
  `python3 tools/gen_vectors.py`.
- **Signed things are forever.** A change must not make a gratitude that
  verified under an earlier dzq/1.x stop verifying. New attributes mean a
  new schema with a new SAID (SPEC §8).
- **Schemas** in `schemas/` are byte-exact. Changing one byte changes its
  SAID; add a new schema instead.
- Keep the reference verifier dependency-free apart from an Ed25519
  library, and readable rather than fast.
- Second implementations: open an issue with your results on the vectors;
  disagreements are how the spec gets precise.
