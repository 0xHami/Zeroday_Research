# VULN-006 — JsonPath: attacker-controlled query causes unbounded node-set / re-parse DoS (three sinks)

**Software**: Symfony (the Symfony PHP framework)
**Repository**: https://github.com/symfony/symfony
**Affected version**: 8.2.x-dev — commit-pinned, no tagged release (branch `8.2`)
**Status**: CONFIRMED (super-linear CPU blowup demonstrated for sinks (a) and (b); (c) scans uncapped text)
**Severity (static)**: Medium (CVSS 3.1 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`)
**Confidence**: 7/10
**Confidence reasoning**: Super-linear scaling proven dynamically against the live source (b ~N^1.97, a ~bytes^2.04); unauth wherever the attacker controls the JsonPath query (the component's documented use case), but availability-only and gated on an integrator exposing a JsonPath-query endpoint.
**Target commit**: e6df33ba170c94e68f907712798cdaa9aa10bc05
**Validated at**: 2026-10-02T21:59:56Z

## Preconditions
- The new `symfony/json-path` component present in the source tree (it is, under `src/Symfony/Component/JsonPath`). It is not required by the lab's `composer.json`, so the PoC registers a one-line PSR-4 autoload shim pointing at the mounted source (`/src/src/Symfony/Component/JsonPath`). This does not change component behaviour — it only makes the class loadable; the uncapped algorithms are the vendor's shipped code.
- The documented/realistic reachability is any app that evaluates a **client-supplied** JsonPath query via `JsonCrawler::find()` (filter/search UIs, JSON-transform endpoints). No such route is wired in the lab, so validation is component-level.
- I confirmed the uncapped code is present at this commit (read from source, cited below).

## Request
Attacker-controlled JsonPath query strings (all tiny), each against a runtime-generated document. Exact invocation in `request.http`; entry point `exploits/VULN-006/run.sh`:
- (a) `$..*..*` (7 bytes) vs a nested tree document (branch 4, depth 4/5/6).
- (b) `$.arr[?@.x==$.y]` (16 bytes) vs `{"y":-1,"arr":[{"x":0}..{"x":N-1}]}` for N = 500/1000/2000.
- (c) `$[?(@.a=="A…(25k/50k/100k A's)…" && @.a)]` vs `{"a":1}`.

## Response
See `response.txt` / `run.log`. Key timings:
- (b) N=500→0.105s, N=1000→0.373s, N=2000→1.620s → fitted exponent **time ~ N^1.97** (quadratic); last doubling ×4.3 (linear would be ×2).
- (a) fixed 7-byte query; doc 2381→9549→38221 bytes → 0.0012s→0.0164s→0.3417s; node-set 912→5008→**25488** nodes; **time ~ bytes^2.04** (super-linear).
- (c) 25k/50k/100k filter chars → 0.014s→0.024s→0.048s: the tokenizer scans the full uncapped filter text (then the query is rejected by `MAX_FILTER_EXPRESSION_LENGTH=10000`, which is enforced *after* `tokenize()` has run).

## Observation
Three independent uncapped algorithms, each confirmed in source at this commit:
- **(a) recursive-descent node-set explosion** — `JsonCrawler.php:809-827` `evaluateRecursive()` `array_merge`s every descendant with **no node-count cap** (`:822`); chained descendant segments compound in `evaluateTokensOnDecodedData` (`:184-187`). A 7-byte query returns a working set of 25 488 nodes from a 38 KB document, growing ~bytes^2. On a deeper document a 10-byte query (`$..*..*..*`) against a 611 KB doc did not finish in 110 s under a 64 MB limit, while benign `$.*` finished in 0.07 s — i.e. single-request CPU exhaustion.
- **(b) per-element whole-document re-decode** — `evaluate()` `json_decode`s the entire raw document on every call (`JsonCrawler.php:126-127`, no memoization). `evaluateFilter()` iterates every element (`:518-519`) and a `$`-rooted operand re-enters the public `evaluate()` per element via `evaluateScalar` (`:697` `return $this->evaluate(new JsonPath($expr))[0] ?? null;`). So `$.arr[?@.x==$.y]` over an N-element array triggers **N full re-decodes of the O(N)-sized document → O(N²)**. Confirmed: time ~ N^1.97.
- **(c) uncapped tokenizer scan** — `JsonPathTokenizer::tokenize()` (`:39-61`) applies no length guard; the length cap lives only in `JsonCrawler`'s later `validateFilterExpression`/`evaluateFilterExpression` (`:531`, `:1088`), i.e. *after* `tokenize()` (called at `JsonCrawler.php:97`) has already scanned the full filter text. Minor/polynomial, as the report anticipated; dominated by (a)/(b).

`stopOnFirstError`-style early exits do not help: in (b) the filter value `y=-1` never matches, so every element is walked.

## Side effects
None. Read-only CPU/time measurement; no state created. Each PoC run is bounded (< ~2 s per step) and never exhausts the 16 GB host.

## Research & references
- **RFC 9535 (JSONPath)** — §2.5.2 descendant segment `..` and §4 Security Considerations explicitly flag attacker-controlled queries / descendant selection as a resource-consumption hazard. The component implements `..` with no node budget.
- **Sibling CVE: CVE-2026-45756** — "JsonPath evaluates attacker-controlled regular expressions in match()/search() without limits" (ReDoS). The published fix clamps `pcre.backtrack_limit` for the regex *match/search* sink (`safeRegexMatch`, `JsonCrawler.php:1190-1200`). The three sinks here are **different** (node-set `..`, per-element `$`-reparse, tokenizer-stage length) and remain uncapped at `e6df33ba`.
- **CWE-407** Inefficient Algorithmic Complexity; **CWE-1333** Inefficient Regular Expression Complexity (sink c).
- **OWASP** — "Denial of Service Cheat Sheet" and WSTG application-level/asymmetric-resource-consumption DoS: request cost should be bounded ~linearly by input size; here a ~16-byte query buys O(N²) work.

## Suggested fix
See `writeup.md` — cap the recursive-descent node-set / number of `..` segments; memoize the decoded document for the lifetime of one `evaluate()` call-tree so `$`-rooted filter operands do not re-`json_decode` per element; apply the length cap (and/or clamp `pcre.backtrack_limit`) inside `JsonPathTokenizer::tokenize()` before the validation regexes run.
