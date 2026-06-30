# Known Issues

> Offline issue log (the `gh` CLI was unavailable when this was filed). Migrate
> these to GitHub Issues when connectivity is restored.

---

## Knowledge Graph deduplication loses multi-source provenance

**Status:** Deferred to v0.5.1.

### Summary

`InMemoryKnowledgeGraph` deduplicates identical assets by `type:value`, causing
passive and browser observations of the same header to collapse into one asset.
This prevents the verification pipeline from distinguishing multiple observation
sources, causing `test_agreement_missing_reported_as_verified` to fail.

### Detail

`InMemoryKnowledgeGraph.add_asset` (`src/recon_platform/knowledge_graph/graph.py`)
keys assets by their stable `type:value`. When the passive source (`http_headers`)
and the browser source (`network_capture`) both emit an identical `HEADER` asset,
the two collapse into a single asset that retains only the first-added `source`.

`collect_header_maps` (`src/recon_platform/verification/headers.py`) then derives
an empty browser map, so `browser_observed` is `False`. As a result a header that
is absent from both sources is graded `LIKELY`-missing instead of
`VERIFIED`-missing, and no "verified missing" finding is produced — so
`tests/test_verification.py::test_agreement_missing_reported_as_verified` fails
its `assert verified_missing`.

The pure-logic unit tests pass because they call `compute_header_verifications`
directly, bypassing the lossy graph dedup.

### Scope / impact

- Pre-existing on `main`; **unrelated to Phase 5** (it fails identically with all
  Phase-5 changes stashed, and Phase 5 touches none of the verification path).
- Affects cross-source corroboration whenever two sources observe an
  identical-value asset.

### Proposed fix (deferred)

Make the central knowledge-graph merge preserve *multiple observation sources* for
an identical-value asset (e.g. union sources on merge), and have
`collect_header_maps` consume that provenance. This changes Phase-1 core dedup
semantics that every layer depends on (attribute precedence, confidence
selection, serialization, report output), so it warrants its own reviewed change
with dedicated tests. Natural home: the Phase 15 (Analysis & Correlation
Intelligence) provenance work.

> Per the v0.5.0 acceptance, **implementation code must not be modified for this
> issue** in the Phase 5 milestone. See *Known issues* in
> [PROJECT_STATUS.md](PROJECT_STATUS.md) and [CHANGELOG.md](CHANGELOG.md).
