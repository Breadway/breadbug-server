# Fuzzy clustering evaluation

Reports with no stable fingerprint (behavior reports, freezes without a
stack, manual reports and feature requests) are matched by text similarity.
Two labelled sets measure the matcher:

- `tests/fixtures/fuzzy_eval.json` (v1): 8 problems, 3 wordings each, written
  while the built-in hashing embedder was being tuned. Its wordings share
  vocabulary, so it flatters bag-of-words matching.
- `tests/fixtures/fuzzy_eval_v2.json` (v2): 10 problems, 4 wordings each,
  written against the symptom with deliberate synonyms, plus 9 hard negatives
  (different problems that read alike). This is the number to trust.

| Embedder | Threshold | v1 precision | v1 recall | v2 precision | v2 recall |
|----------|-----------|--------------|-----------|--------------|-----------|
| built-in hashing (unigrams + bigrams) | 0.30 | 1.00 | 0.71 | 0.25 | 0.02 |
| `all-MiniLM-L6-v2` (local TEI) | 0.50 | 1.00 | 1.00 | 0.98 | 0.67 |

The hashing embedder collapses on v2 because it only matches shared words:
"battery drains fast while asleep" against "high power use while suspended"
scores 0.00. It remains the zero-dependency fallback when no embedding
service is configured.

`all-MiniLM-L6-v2` is served on the Hestia Arc A380 and exposed to the
container through the host-side TEI `/embed` shim (`host.docker.internal:7311`,
proxying to the llama.cpp server on 7310). The threshold is model-specific and
set with `BREADBUG_FUZZY_THRESHOLD`.

## Threshold choice for MiniLM

| Threshold | v2 precision | v2 recall | Hard negatives above it |
|-----------|--------------|-----------|-------------------------|
| 0.45 | 0.93 | 0.72 | 9 of 9 |
| 0.50 | 0.98 | 0.67 | 9 of 9 |
| 0.55 | 1.00 | 0.53 | 8 of 9 |

0.50 is the default because a wrong merge hides a bug while a missed merge
costs one triage click. Precision matters more: clusters cannot be split
today (only merged), so a false merge is not undoable.

## What this does and does not do

- Same app and same report kind only; never across either.
- Compared against the centroid of each live fuzzy cluster; the best match at
  or above the threshold wins, otherwise a new cluster starts.
- The centroid is the running mean of its reports' vectors. A manual merge
  rebuilds the survivor from all its stored reports, so the wording that was
  folded in matches the next time it arrives.
- Fewer than three distinct meaningful words means nothing to match on: the
  report is stored unclustered.
- Report text is data. It is only sent to the local embedding service; it is
  never executed, templated, or sent to a third party. The service URL must
  resolve to loopback or private addresses, checked at startup and on every
  call.
- Assignment is greedy and arrival-order dependent. On v2 at 0.50 the 40
  reports form 16 clusters for 10 problems: some duplicate pairs score below
  the threshold and only merge by hand.
- Small sentence models are weak on fine distinctions. These different
  problems score 0.52 to 0.91 with MiniLM and would merge at 0.50:
  "video playback stutters in jellyfin" / "audio playback stutters in
  jellyfin"; "wifi disconnects after waking" / "bluetooth disconnects after
  waking". A cross-encoder reranker on the candidate pair is the next step if
  that becomes a real triage problem.

## Running the evaluation

The hashing embedder is covered by `tests/fuzzy.rs` in normal CI. A real
backend needs its service running:

```sh
BREADBUG_EVAL_EMBED_URL=http://127.0.0.1:8181/embed \
BREADBUG_EVAL_EMBED_MODEL=all-MiniLM-L6-v2 \
BREADBUG_EVAL_THRESHOLD=0.50 \
  cargo test --test fuzzy_embedding_eval -- --ignored --nocapture
```

The test fails below 0.90 precision or 0.55 recall on either set.

For a production-like check, point `BREADBUG_EVAL_EMBED_URL` at the Hestia Arc
shim (`http://host.docker.internal:7311/embed`) from a container with
`host.docker.internal:host-gateway` mapped.

## Matching rules

- Same app and same report kind only; never across either.
- Compared against the centroid of each live fuzzy cluster; the best match at
  or above the threshold wins, otherwise a new cluster starts.
- The centroid is the running mean of its reports' vectors, renormalised.
- Report text is the user's words (title, want, notes weighted by repetition),
  panic messages and locations, warn/error log lines, symbol names and recent
  event names. The report kind is not part of the vector: it is already a hard
  filter, and including it would inflate every same-kind score.
- Vectors are stored with a model name and only compared within the same
  model. `cluster::reembed_stale` rebuilds clusters whose model changed on the
  hourly maintenance pass and at startup.
