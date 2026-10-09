# Fuzzy clustering evaluation

Reports with no stable fingerprint (behavior reports, freezes without a
stack) are matched by text similarity. `tests/fuzzy.rs` measures the matcher
on `tests/fixtures/fuzzy_eval.json`: 8 problems, 3 deliberately differently
worded descriptions each, so 24 same-problem pairs and 252 different-problem
pairs.

| Embedder | Threshold | Precision | Recall | False positives |
|----------|-----------|-----------|--------|-----------------|
| built-in hashing (unigrams + bigrams) | 0.30 | 1.00 | 0.71 | 0 |

The highest similarity between two different problems in the set is 0.27, so
0.30 is just above the noise floor. Raising it to 0.35 drops recall to 0.46.
The test fails if precision falls below 0.95 or recall below 0.65.

## What this does and does not do

The built-in embedder is a bag of words and bigrams hashed into 256
dimensions. It needs no model download and runs anywhere, but it only matches
descriptions that share vocabulary. Paraphrases with no words in common are
missed (the 29% of same-problem pairs that fall below the threshold), so
duplicates may land in separate clusters; triage can merge them by hand.
Precision matters more than recall here: a wrong merge hides a bug, a missed
merge only costs a click.

For better paraphrase handling set `BREADBUG_EMBED_URL` to a local
sentence-embedding service (text-embeddings-inference style: `POST` with
`{"inputs": ["..."]}` returning `[[f32...]]`) and `BREADBUG_EMBED_MODEL` to its
name. Only loopback and private addresses are accepted so report text never
leaves the machine. Vectors are stored with a model name and only compared
within the same model; `cluster::reembed_all` rebuilds centroids when the
model changes. Re-run the evaluation and retune `BREADBUG_FUZZY_THRESHOLD`
for the new model before relying on it.

## Matching rules

* Same app and same report kind only; never across either.
* Compared against the centroid of each live fuzzy cluster; the best match at
  or above the threshold wins, otherwise a new cluster starts.
* The centroid is the running mean of its reports' vectors.
* Fewer than three distinct meaningful words (ignoring the report-type
  label) means nothing to match on: the report is stored unclustered.
* Report text is data. It is only tokenised and hashed; it is never executed,
  templated, or sent to a third party.
