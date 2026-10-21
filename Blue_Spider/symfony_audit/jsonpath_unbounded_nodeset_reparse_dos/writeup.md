# VULN-006 — JsonPath: attacker-controlled query causes unbounded node-set / re-parse DoS (three sinks)

| | |
|---|---|
| **Status** | CONFIRMED (super-linear CPU blowup demonstrated for sinks (a) and (b); (c) scans uncapped text) |
| **Confidence** | 7/10 |
| **Severity** | Medium — CVSS 3.1 5.3 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| **Component** | JsonPath (new `symfony/json-path`) |
| **Target commit** | e6df33ba170c94e68f907712798cdaa9aa10bc05 |
| **Location** | `targets/symfony/src/Symfony/Component/JsonPath/JsonCrawler.php:126-127, 184-187, 518-519, 697, 809-827` · `Tokenizer/JsonPathTokenizer.php:39-61` |

## Summary
The documented use of the new `JsonPath` component is evaluating a **client-supplied** JsonPath query (filter/search UIs, JSON-transform endpoints). Three independent, uncapped algorithms turn such a query into a cheap availability weapon. All three are present at this commit; two were dynamically confirmed to scale **super-linearly** (≈ quadratic) and the third scans attacker text with no length guard. A sibling regex sink in the same component already has a CVE (CVE-2026-45756); these are different, still-uncapped sinks.

## How it works (mechanism & code trace)

### (a) Recursive-descent (`..`) node-set explosion
`evaluateRecursive()` merges every descendant into one list with **no node-count cap**:
```php
// JsonCrawler.php:809-827
private function evaluateRecursive(mixed $value): array {
    ...
    $result[] = $value;
    foreach ($value as $item) {
        if ($this->isArrayOrObject($item)) {
            $childResults = $this->evaluateRecursive($item);
            $result = array_merge($result, $childResults);   // :822  no cap
        }
    }
    return $result;
}
```
Chained descendant segments compound in the token walk, `array_merge`-ing each segment's node list:
```php
// JsonCrawler.php:184-187
foreach ($current as $value) {
    $next = array_merge($next, $this->evaluateToken($token, $value));
}
```
The component caps filter-expression *text* (`MAX_FILTER_EXPRESSION_LENGTH/DEPTH`, `:37-38`) but nothing bounds the number of `..` segments or the intermediate node-list size. A 7-byte query (`$..*..*`) produced a working set of **25 488 nodes** from a 38 KB document, growing ~bytes². A 10-byte `$..*..*..*` against a 611 KB document did not finish in 110 s under a 64 MB limit (benign `$.*`: 0.07 s).

### (b) Absolute (`$…`) operand inside a filter re-decodes the whole document per element
`evaluate()` re-`json_decode`s the raw document on **every** call — no memoization:
```php
// JsonCrawler.php:126-127
$data = json_decode($json, false, 512, \JSON_THROW_ON_ERROR);
```
`evaluateFilter()` iterates every element, and a `$`-rooted operand re-enters the public `evaluate()` once per element:
```php
// JsonCrawler.php:518-519
foreach ($value as $item) {
    if ($this->evaluateFilterExpression($expr, $item)) { $result[] = $item; }
```
```php
// JsonCrawler.php:697 (evaluateScalar, reached for the right-hand "$.y")
return $this->evaluate(new JsonPath($expr))[0] ?? null;   // full re-decode, per element
```
So `$.arr[?@.x==$.y]` over an N-element array runs **N full re-decodes of an O(N)-sized document → O(N²)**. Measured exponent **time ~ N^1.97**. The comparison value never matches, so there is no early exit — every element is walked.

### (c) Tokenizer runs on uncapped filter text
`JsonPathTokenizer::tokenize()` (`:39-61`) has no length guard; `JsonCrawler` enforces `MAX_FILTER_EXPRESSION_LENGTH` only later (`evaluateFilterExpression:531`, `validateFilterExpression:1088`) — *after* `tokenize()` has already run (called at `JsonCrawler.php:97`). A 100 000-char filter is scanned in full before the 10 000-char cap rejects it. Minor/polynomial, as expected; dominated by (a)/(b).

## Why it is a vulnerability
Availability. A well-formed request's server cost is supposed to be bounded ~linearly by its size. Here a ~16-byte query buys O(N²) CPU (b), or a ~7-byte query inflates a 38 KB document into a 25 k-node working set (a). Where the JsonPath query is attacker-controlled — the component's documented purpose — this is an unauthenticated, low-byte, high-amplification single-request DoS of the PHP worker. RFC 9535 §4 explicitly flags attacker-controlled queries and `..` as resource-consumption hazards.

## Reproduction
```bash
cd claude_audit/symfony/exploits/VULN-006
NO_COLOR=1 ./run.sh 2>&1 | tee run.log
```
Expected (abridged): exit 0 and
```
B n=500 ... time=0.1050 | B n=1000 ... time=0.3726 | B n=2000 ... time=1.6198
(b) fitted exponent time~N^1.97 ; last doubling x4.3
A depth=4 nodes=912 time=0.0012 | depth=5 nodes=5008 time=0.0164 | depth=6 nodes=25488 time=0.3417
(a) ... time~bytes^2.04 (super-linear)
==> VULN-006: CONFIRMED — attacker JsonPath query => super-linear worker CPU DoS (sinks a,b,c).
```
The proof is the scaling: doubling N ≈ quadruples (b) time; a 4×-larger document ≈ 18×-s (a) time — both super-linear against a tiny query. (The PoC registers a one-line PSR-4 autoload shim because the lab's `composer.json` doesn't require `symfony/json-path`; it does not alter component behaviour.)

## Impact
Single-request worker CPU/memory exhaustion; a handful of concurrent requests saturate the worker pool. (a) and (b) compound when one query is both `..`-heavy and references `$` inside a filter. No confidentiality/integrity impact. Bounded per request by `max_execution_time`/`memory_limit`, hence Medium.

## Suggested fix
- **(a)** In `evaluateRecursive()`/`evaluateTokensOnDecodedData` abort with a `JsonCrawlerException` once an overall node-count budget is exceeded, and cap the number of `..` segments per query:
  ```php
  // JsonCrawler.php:819-823 (pseudo)
  if (\count($result) > self::MAX_RESULT_NODES) {
      throw new JsonCrawlerException($this->query, 'result node-set budget exceeded');
  }
  ```
- **(b)** Memoize the decoded document for the lifetime of one `evaluate()` call-tree (decode once, reuse) so `$`-rooted filter operands don't re-`json_decode` per element — e.g. cache keyed on the raw string / stream offset.
- **(c)** Enforce the length cap (and/or clamp `pcre.backtrack_limit` as `safeRegexMatch` already does) inside `JsonPathTokenizer::tokenize()` *before* the validation regexes run.

## References
- RFC 9535 (JSONPath) §2.5.2 (descendant segment `..`), §4 Security Considerations.
- CVE-2026-45756 — sibling regex ReDoS sink (`match()`/`search()`) in the same component; the fix does not cover (a)/(b)/(c).
- CWE-407 (Inefficient Algorithmic Complexity); CWE-1333 (Inefficient Regular Expression Complexity, sink c).
- OWASP Denial of Service Cheat Sheet; WSTG asymmetric resource-consumption DoS.

## Known Issue Check

| | |
|---|---|
| **Verdict** | NOT KNOWN (no matching public disclosure found) |
| **Confidence (not previously known)** | 75 / 100 |
| **Checked on** | 2026-10-21 |
| **Method** | Web search of CVE/NVD, GitHub Security Advisories, vendor advisories, issue trackers, huntr/HackerOne/Snyk |

**Searches performed (proof of "nothing found"):**
1. `symfony.com/blog/category/security-advisories` pages 1–7 (all advisories back to Nov 2024) — the only JsonPath advisory is CVE-2026-45756 (regex ReDoS in `match()`/`search()`); nothing on recursive descent, node-set size, re-decoding or tokenizer limits
2. `github.com/symfony/symfony/security/advisories?state=published` — no JsonPath entry other than the regex CVE
3. CVE-2026-45756 advisory text — scope is `preg_match()` catastrophic backtracking; the only fix is lowering `pcre.backtrack_limit` to 10000 around regex calls; no other limits mentioned
4. symfony/symfony issue tracker query `JsonPath recursive / descendant / DoS / performance / memory / limit` — no relevant issue or PR
5. Current `src/Symfony/Component/JsonPath/JsonCrawler.php` on branch `8.2` — constants are only `REGEX_BACKTRACK_LIMIT`, `MAX_FILTER_EXPRESSION_LENGTH`, `MAX_FILTER_EXPRESSION_DEPTH`; `evaluateRecursive()` has no depth/count guard, `json_decode` runs on every `evaluate()` call, and `$`-rooted filter operands still re-enter `evaluate()`, i.e. the three sinks are unfixed at head. (General web search quota was exhausted for this session, so verification relied on direct advisory, docs, source and issue-tracker fetches.)

**Related but distinct public references** (same class or component, not this bug):
- CVE-2026-45756 (symfony/json-path < 7.4.12 / 8.0.12) — attacker-controlled regex in `match()`/`search()`; same component, different sink; its fix (backtrack limit) does not bound `..` expansion, per-element re-decode, or tokenizer input length
- CVE-2026-109413 (YAML inline lexer unbounded recursion) and CVE-2026-109449 (ExpressionLanguage unbounded nesting) — same resource-exhaustion class in other Symfony parsers
- RFC 9535 §4 — generic security-considerations note that `..` and attacker-controlled queries are resource hazards; not a Symfony-specific disclosure

**Reasoning:** The only public JsonPath advisory covers a different sink (regex backtracking), and the component's current source still lacks any node-count budget, descendant-segment cap, decoded-document memoization, or pre-tokenize length check, so no upstream fix or issue describes these three sinks. Caveats: the component is new (7.3+) and received a wave of third-party security audits in May 2026, so a private report to security@symfony.com could already exist, and algorithmic-complexity DoS is a common class that maintainers may treat as a hardening request rather than a vulnerability.
