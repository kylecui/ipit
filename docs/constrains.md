Important implementation note:

`rules/service_catalog.yaml` is a semantic enrichment source, not a final truth source.
Matches from this file should:
1. add tags
2. reduce false positives
3. influence confidence and explanation

They should NOT:
1. directly override strong malicious evidence
2. directly set final verdict to benign
3. be treated as exact ownership proof when only weak hostname heuristics are matched
