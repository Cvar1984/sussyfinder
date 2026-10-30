# Rules for agents working on SussyFinder

Read this before changing anything. It collects the maintainer's standing rules
and the decisions behind the current code, so they don't get re-litigated.

## What this is

A PHP webshell/malware scanner dropped onto (often old, cheap, shared) web
hosts. `main.php` is the whole product: PHP backend + HTML + client-side JS in
one self-contained file, no dependencies. `README.md` documents the maths
(entropy, median/MAD z-scores, threat score, anomaly rules) for users.

| Path | Role |
|---|---|
| `main.php` | The scanner. The only file under active development. |
| `main-cli.php` | Old CLI variant. **Parked**, see rules. |
| `whitelist.txt` / `blacklist.txt` | MD5 lists, fetched from GitHub raw at runtime. `push.sh` dedupes and publishes them. |
| `test/run` | The one entry point for tests, benchmark and ML training (`test/run` lists the commands; `test/README.md` maps the tree). |
| `test/corpora/positive/`, `test/corpora/noise/` | Sample submodules: webshells vs legitimate code. Never commit changes inside them. |
| `test/PHTest/` | Submodule: Docker builds of legacy PHP versions. See `test/PHTest/README.md`. |

## Hard rules

1. **PHP4 syntax in all PHP.** `array(...)` never `[...]`; no closures, `fn`,
   `??`, `?:`, `?->`, namespaces, type hints, etc. Plain `cond ? a : b` is
   fine. Ignore IDE hints suggesting modern syntax.
2. **Runtime floor is PHP 4.3** (4.1/4.2 lack `token_get_all`). Version and
   host differences are settled once, in `main.php`'s compatibility section:
   check a builtin with `functionAvailable()` (it honours `disable_functions`)
   or call it through `callIfAvailable()`; write JSON with `jsonEncode()`
   (never define `json_encode`: PHP 5/7 can't redefine a disabled builtin);
   token constants a PHP lacks are defined there as negative sentinels, and
   `getFileTokens()` turns PHP 8's new tokens back into PHP 7's.
3. **No backward-compat shims.** When a field, format or signature changes,
   change every reader and writer in the same edit. Never accept "old or new".
   Client JS and server PHP ship together in one file, so there is no one to
   stay compatible with.
4. **`main-cli.php` is parked.** Don't port `main.php` changes to it and don't
   add cross-file sync checks unless the maintainer revives it.
5. **Never let the scanner delete test data.** A blacklist hit `unlink()`s the
   file. Run the web UI / AJAX against the corpora only with the repo mounted
   read-only (as `test/run matrix` does) or on a copy with the lists off (as
   `test/run ui` does). Never run `main-cli.php` on `test/`.
6. **Measure detection changes.** Any change to needles, weights, signals or
   anomaly rules gets a before/after `test/run bench` run, reported in the
   summary; touching the tokenizer helpers also gets `test/run matrix`. Don't
   claim numbers you didn't run.
7. **Git:** commit only when asked, on `main` (the maintainer's workflow).
   Stage specific files; never `git add -A` (it would sweep in the corpora).
8. The in-page JS is modern (ES2015+, `const`, arrows, spread). The PHP4 rule is
   about PHP only.

## How main.php fits together

- **Server** (`scanReadablePaths`) reads each file once, hashes it
  (`md5($content)`), skips whitelisted files, and returns a feature row per file:
  `path, size, mtime, ctime, owner, entropy, total_tokens, matched_tokens, md5,
  is_blacklisted, is_htaccess, duplicate_of, verified, error, is_unreadable`.
  `verified` (the release a file is byte-identical to, or false) is set by
  `actionProcess()` through `checksumVerified()`, not during extraction, so
  the corpora's cached rows never depend on the network.
  Stat calls (`filectime`/`fileowner`) happen **before** a blacklist unlink.
- **Detection primitives:** `getFileTokens` (token_get_all, minus literal text
  inside `"..."`, backticks and heredocs: old tokenizers emit that text as
  `T_STRING`), `tokenTextSet`
  (ignores string/HTML/comment content and method names after `->` / `::` /
  `function`; strips a leading `\`), `compareTokens` (isset lookups against the
  `$tokenNeedles` weight map), `findStructuralSignals` (pseudo-tokens, below),
  `shannonEntropy` (whole-file bytes). `codeTokens()` walks the tokens once
  and `analyzeContent()` hands the result to all of them.
- **Needle names match a global call only.** `tokenTextSets()` ('match' set)
  drops a needle name used as a class (`new Exec()`, `Exec::run()`), a
  namespace segment (`namespace App\System;`, `use Vendor\Exec;`, one token on
  PHP 8, pieces before) or a member (`->exec`, `::exec`, `function exec`). A
  name counts only when a `(` follows and it is not a namespaced piece or
  `new`. This killed most rule false positives (framework `tests/` and vendor
  paths full of `...\system\...`). Don't widen it back.
- **Pseudo-tokens** are prefixed `@`, which no real PHP token can match:
  `@input_call` `$_GET['a']()`, `@preg_e`, `@concat_name` (name hidden in a
  string; the recovered name is added too), `@callback_exec` (an execution
  function named as a string for a callback, e.g. `array_map('assert', ...)`;
  only names rarely seen as plain data, and not after a capability check like
  `function_exists`), `@input_include` (`include`/`require` of a request var,
  `include $_GET[...]`; `$_SERVER` is excluded as a routine benign base),
  `@wrapper_include` (`include`/`require` of a `php://` or `data:` stream, e.g.
  `include('php://input')`; `phar://` excluded, it appears in legit phar stubs),
  `@halt_payload`, `@dyn_call`, `@long_line`. Their weights
  live in `$tokenNeedles` next to real tokens.
- **Client** scoring lives between `// --- Client-side threat scoring` and
  `// --- End client-side threat scoring ---`. The tests (`test/lib/scanner.js`)
  execute exactly that slice, so keep it self-contained (no DOM) and keep the
  markers. Needle weights and roles come from PHP (`$tokenTiers`,
  `$tokenRoles`); never copy needle lists into the JS.
  `HIGH_ENTROPY` there is the single entropy threshold used everywhere.
- **`define('SUSSY_LIB', true); include 'main.php';`** stops at the bootstrap
  (before AJAX and HTML), after configuration, compatibility, engine, network
  and actions are defined. The tests rely on it. Settings are constants made
  with `settingDefault()`, so defining one first overrides it.
- **Access:** there is deliberately no login or access key (the maintainer
  doesn't want one). Every AJAX request must carry the
  `X-Sussy-Request` header (the CSRF check); the page sends all of them
  through `postAction()`. Read request values with `inputValue()` /
  `postList()`, which undo magic quotes; never `$_POST` directly.
- **AJAX:** POST `ajax_action` = `scan` | `process` | `mhr_check` | `mhr_unlink` | `clear_cache`.
  Paths travel **`rawurlencode()`d in both directions** (`path`, scan lists,
  `mhr_unlink` results; the page works out `duplicate_of` from each row's md5),
  so names
  that aren't valid UTF-8 survive JSON. The page decodes them for display
  (`decodePath()`) and sends back `pathRaw`. Lists go as **comma-separated
  strings** (`postList()`), not arrays or JSON: one field stays under
  `max_input_vars`, and no `json_decode` is needed on old PHP. Never use NUL
  as a separator in a request: hardened hosts (Suhosin's default
  `disallow_nul`, some WAFs) strip or drop such values, which silently emptied
  every scan on a real host. Responses go
  through `ajaxRespond()`, which folds in captured PHP warnings and encodes
  with `jsonEncode()` (UTF-8-safe), so the body is never empty, and gzips it
  when the browser accepts gzip (unless `zlib.output_compression` already
  does). `scan` lists one page (`after` = the previous reply's `next`, until
  `next` is null) and doesn't send whole paths: `dirs` lists each directory
  of the page once (`/` left unencoded) and `readable` / `not_readable` are
  flat `[dir index, name, ...]` lists, joined by the page as
  `dirs[i] + '/' + name` when a batch is sent (453,627 files: 61 MB of JSON
  as whole paths, 25 MB so, ~3 MB gzipped). A file `process` can't find any
  more comes back as a `gone` row, not a warning: a retried batch may have
  deleted it the first time.
- **The scan in the page** (`pumpScan()`): listing pages and `process`
  batches share `MAX_PARALLEL` request slots, starting at 1 (the first batch
  fills the download cache), +1 per 10 clean batches, halved on a busy
  reply (`isOverloaded()`: 429/502/503/504/508), which is retried whole
  after a wait, or on no answer (`NoAnswer`: a failed, reset or cut-off
  connection; Firefox reports a reset as AbortError), retried whole once,
  then bisected like any other failure. A listing page with no answer is
  asked for again with half the `limit` and `seconds` (the server never
  goes above its own `LIST_PAGE_FILES` / `listSeconds()`). Results
  are applied in batch order. A row is passed through `withMlScore()` as it
  arrives: the ML score is stored and the bitmaps dropped, so scoring reads
  `mlScore`, never `ml_features`. When the scan ends `markDuplicates()` sets
  `duplicate_of` (newest copy is the original, then path order: independent
  of arrival order) and all rows are scored together, since the median/MAD
  statistics need every file. The scored rows then are the scan's rows
  (`rawFileData === analyzedData`): one copy per file. `_scan` is the
  running scan; replies for any other are dropped (cancel, rescan).
- **`mhr_unlink`** deletes only files whose *current* md5 MHR confirms in that
  same request. Never make it trust the browser's path list.
- **Listing** (`listFiles()` → `listWalk()`): `$pattern` is one complete
  regex matched against the file name (validated before use). Names are
  walked in byte order (`sort(SORT_STRING)`), so a page resumes after the
  last path it handled; the server keeps no state, and the cursor is only
  compared with names, never opened. A page ends at `LIST_PAGE_FILES` files
  or `listSeconds()`. Regular files only (a FIFO would hang `md5_file`).
  Symlinked files are listed; symlinked dirs are never followed (inside the
  root they are listed at their real path anyway; outside, warned), which
  also rules out loops. Anything unscannable is reported with
  `trigger_error()`, not skipped silently.
- **Search** (`compileSearch()`): the query is compiled once per change into
  one test per row (`searchMatcher()`); `passesTableFilters()` only calls it.
  A new field goes in `SEARCH_TEXT` / `SEARCH_EXACT` / `SEARCH_NUMBERS` /
  `SEARCH_FLAGS` and in the `#searchHelp` table. `near:` (`nearTest()`) takes a
  scanned file's path or else a query of targets (compiled recursively, as is
  a bare `(group)`), looked up in `analyzedData`, so the compiled query is
  also rebuilt when that changes. An unknown `field:` is plain
  text (`c:\x`). Bad terms are left out and named in the box's tooltip.
  Other code that sets a search writes a query (`is:blacklisted`,
  `path:"..."`), never a magic value.
- **Charts** share one selection (`_chartSelection`, a Set of paths) and one
  hover (`_chartHover`). `shouldShowFile()` = `passesTableFilters()` + that
  selection, and it's what both the table and the charts use (charts fade
  what it hides). `renderTable()` ends in `syncCharts()`, which rebuilds the
  charts for a new dataset and otherwise just redraws them, so every filter
  change reaches the charts through the table. New charts go through
  `makeChart()` (DPR-sized canvas, shared drag/hover/click handling); don't
  add `document`/`window` listeners inside it: the shared ones are registered
  once at load.
- **Page output:** file names are attacker-controlled. Escape with
  `escapeHtml()` for HTML, and never put data inside inline `onclick="f('…')"`:
  use a `data-` attribute (the document click listener handles `data-copy`,
  `data-vt`, `data-filter-path`).
- **Downloads** all go through `httpRequest()`: verified TLS (the blacklist
  deletes files), a fresh cURL handle per request, else PHP streams; it
  returns the status and body, asking for gzip where it can decode it
  (cURL's `CURLOPT_ENCODING`; streams only with `gzdecode()`, PHP 5.4+).
  `fetchText()` is the one way to get a list, manifest or model: an http(s)
  URL or a local file, a 404 optionally quiet, a host that didn't answer not
  asked again in that request. **Download cache** (owner's call: "cache, but
  deletable"): `fetchText()` keeps each http(s) download, and a 404, as a
  file in `CACHE_DIR` until `cacheClear()` deletes it: the page's **Refresh
  lists** button (`clear_cache`) or removing the folder. The default is
  `sussyfinder-<hash of __FILE__>` in the system temp folder, found by
  `tempDir()` in the compatibility section (`sys_get_temp_dir()` behind
  `functionAvailable()`, then `upload_tmp_dir`, TMPDIR/TMP/TEMP, `/tmp`; only
  a writable one, so open_basedir is respected). The temp folder is shared
  with other hosting accounts, which could create the folder first and plant
  a blacklist (deletes files) or whitelist (hides shells): `cacheDirIsOwn()`
  only trusts a folder owned by the user PHP runs as (the owner of a probe
  file written there) with no group/other write bit; it is created 0700.
  Written to a temp file and renamed, so a parallel batch never reads half a
  file. Network failures are never cached. No usable folder: every request
  downloads again. A session
  cache was tried and dropped: a 1.2 MB list in the session cost every batch
  ~30 MB and ~150 ms, and it could not be cleared on demand.
- **MHR** (Team Cymru) needs PHP 5.2+ (`json_decode`) and HTTPS; on older PHP it
  returns a clear error. A `json_decode` fallback was deliberately not added:
  legacy builds have no HTTPS, so it could never run.
- **VT button** on each row opens the VirusTotal report for the file's MD5.

## Testing

```sh
php -l main.php           # syntax
test/run                  # the commands; test/README.md maps the tree
test/run unit             # PHP self-check + JS unit tests (seconds)
test/run bench --list     # detection rates on the local php, with misses and false positives
test/run bench --tokens   # + per-token webshell vs benign counts, for tuning weights
test/run matrix           # every PHP version x php.ini profile in Docker + page/AJAX check
test/run ui               # the page in headless Chrome (CHROME_BIN)
test/run all              # unit + bench + ui
test/run checksums --write # rebuild checksums.txt after retraining or changing the rules
```

The baseline is whatever `test/run bench` prints on the current commit: run
it before and after a change and compare, rather than quoting old numbers.
`test/run matrix` must match the local php on every container, except for the
known tokenizer differences below; its summary table lists any file that
matches differently than on the newest PHP. Each run also checks the listing
fixture (FIFO, symlink to `/`, symlinked file, double extensions, `.user.ini`,
a Latin-1 and a quoted name) and, per container, that a request without the
CSRF header is refused.

Known, accepted differences between PHP versions:
- PHP 5.6 to 7.2 tokenize some modern code differently (a 7.3 tokenizer
  change), so a few files match a token less.
- With PHTest's legacy builds (`test/run matrix --php all`): 4.1/4.2 fail
  (below the floor, reported as n/a, not a failure). PHP 4.3.0's tokenizer
  segfaults on some modern WordPress files; the runner skips them and
  resumes, like the UI's one-by-one retry. 4.3.0 also labels AJAX replies
  text/html (a bug in that PHP build), which is harmless. On 4.3.x/5.0.x,
  files with nowdocs (`<<<'EOT'`, PHP 5.3+) gain `@dyn_call`: old tokenizers
  can't parse them, and such files can't run on those hosts anyway.
- `total_tokens` differs slightly on old PHP (tokenizer differences).

The benchmark zeroes mtime/ctime because the corpora were copied at different
times and would otherwise be "detected" for free. So the ctime-gap, mtime and
rare-owner signals are **not** measured by the bench, and neither is the
`uploads/` rule (no corpus file lives there).

## Decisions already made, so don't redo them

Each was measured with the benchmark when it was made; re-measure with
`test/run bench` (`--tokens` for per-token counts) or `test/run train` before
revisiting one.

- Entropy is whole-file bytes, threshold 5.5: about half the webshells are
  above it and almost no benign files. "Longest string literal" entropy was
  tried and was worse at useful thresholds.
- Z-scores are median/MAD (Iglewicz & Hoaglin), with a mean-absolute-deviation
  fallback when MAD = 0. The ctime−mtime gap has a 1-day scale floor. Entropy
  z is one-sided (high side only).
- `zSize` and `zSusp` are computed and shown but **not** anomaly triggers: each
  caught no webshell the other signals missed and added false positives.
- Removed signal `@string_heavy`: it fired on far more benign files than
  webshells.
- `preg_replace`, `call_user_func(_array)`, `register_shutdown/tick_function`
  are weight 0.1: they appear in many benign files and add nothing on their
  own; the dangerous `/e` form is scored as `@preg_e`.
- "User input + `@dyn_call`" is **not** treated as code execution: WordPress
  uses `$callback(...)` identically. Only the direct `$_GET[...](...)` shape
  (`@input_call`) is critical. Real taint tracking would be the next step:
  track `$x = $_GET[...]` then `$x(...)` in `findStructuralSignals`, and
  measure it with the bench.
- An AST parser (npm `php-parser`, nikic/PHP-Parser) was rejected: it would
  force shipping full file sources to the browser or require PHP 7+, would
  fail on malformed/legacy malware, and would recover only a handful of the
  misses.
- Short open tags (`<?if(...)`) are rewritten to `<?php ` before tokenizing,
  and `<?xml` stops being one, so detection doesn't depend on the scanning
  host's `short_open_tag` (it did: a local run missed `shell_exec` in a shell
  that a container caught). `<?=` and `<?php` are left alone. PHP 8's new
  tokens are turned back into PHP 7's for the same reason.
- The ML score is part of the threat score (`mlPoints()`: 0 at or below
  `ML_FLOOR` 0.6, 8 at `ML_THRESHOLD` 0.9, 10 at 1.0), not a separate flag.
  `ruleScore` keeps the rules-only part. `ML_FLOOR` 0.6 came from a floor
  sweep: lower adds false positives, higher loses catches. `test/run train`
  prints that sweep on held-out scores; it needs every sample (fetch them
  outside any web root, they are live shells).
- ASP/JSP/Perl shells saved as `.php` hold no PHP for the tokenizer to read;
  `@foreign_code` catches them instead.
- **Injected test** (`test/php/inject.php`, `test/lib/inject.js`): real
  backdoors are injected into legitimate files, not dropped as their own file,
  and the surrounding code hides them. Each shell is inserted into a host file
  of its own fold and scored among that project's files. `test/run train`
  prints injected vs on-its-own detection; the ML model alone drops from ~90%
  to ~33% on injected shells (padding dilutes the features). Rules hold up
  (they fire on the shell's own tokens). `--augment` trains on injected copies
  and recovers injected detection, but it is a **rebalance, not a free win**:
  on the combined metric main.php uses (rule score + ML points), at matched
  benign false positives (floor tuned to hold ~0.86% FP) the held-out numbers
  are standalone shells 97.1% -> 90.6% (-6.5pt) and injected shells 72.6% ->
  92.0% (+19pt). At no floor does the augmented model beat the plain one on
  both. It trades the most common case (an uploaded standalone shell) for the
  injected case. Same features and LR format, so ml-model.json stays v2 and
  scores stay stable across PHP versions — the only cost is the recall shift.
  Left off by default (the plain model ships); `--augment` is there for a
  deployment that specifically expects injected backdoors. The gap is closed
  instead by per-unit scoring (below), which needed no retrain or feature bump.
- **Per-unit ML scoring** (`mlFeatureUnits()`, `mlScoreUnits()`,
  `ML_UNIT_FLOOR`): the injected gap is a *scoring*-time problem, not a model
  problem — a shell's features are diluted only because they're averaged over a
  whole big file. So `mlFeatures()` is also run on each top-level function and
  class on its own (emitted in `ml_units`), and the page takes the max over the
  whole file and those units. A unit counts only if it independently clears
  `ML_UNIT_FLOOR`, held at `ML_THRESHOLD` (the bar a whole file clears to be
  flagged). The whole-file score is always one term, so this can't lower a
  score — clean-shell detection and old installs (which ignore `ml_units`) are
  untouched, and `ml-model.json` stays exactly as is. `test/run train` reports
  the held-out rates. Design notes, all measured in the prototype
  (`scratchpad`, grouped-family holdout) and confirmed on the pipeline:
  - The win is large and the standalone cost is nil (the max only ever adds).
  - **Retraining on per-unit samples makes everything worse**, not better:
    labelling every benign function negative pulls down shell-feature weights,
    and a shell file's benign helper functions become noisy positives — clean,
    injected *and* whole-file detection all dropped. The existing whole-file
    model is the right one to score per-unit.
  - The gate is the whole trick. Ungated (any unit counts), benign framework
    functions that merely look odd in isolation (getid3, PHPMailer, a crypto
    lib) roughly double the benign false positives. Gating sub-units at the
    flag threshold removes almost all of that while keeping the injected win,
    because an injected shell and a benign file with one dynamic-dispatch
    function are the *same shape* below the bar — the separation only appears
    once a unit is shell-like enough to be flagged on its own.
  - Besides functions and classes, a head and a tail window
    (`ML_UNIT_WINDOW` tokens) are scored, where an inline shell pasted at the
    top or bottom of a file lands — the common injection no function unit
    catches. Held out this lifts injected detection (combined 80.5% -> 84.5%,
    ML alone 63% -> 71%) for +0.2pt benign false positives (~0.2% -> ~0.3% ML
    only). It works because a file's head and tail are usually declaration
    boilerplate, not shell-like.
  - A sub-unit's `f:ent` feature uses the entropy of its *own* text, not the
    whole file's (`mlUnitEntropy()`); the whole-file vector (units[0], what the
    model trains on) keeps the file's entropy, so this needs no retrain or
    feature-version bump. A packed payload isolated in one unit then reads as
    high-entropy though it's diluted in the whole-file score. Held out: +1pt
    injected (84.5% -> 85.5% combined) for +0.03pt benign false positives.
  - Chopping the *whole* main body into windows (not just head/tail) was
    tried and **rejected**: about the same injected gain but tripled the
    ML-only benign false positives (~0.2% -> ~0.6%, ~1,600 more flagged per
    389k) — an arbitrary window of benign procedural *middle* code has no
    semantic boundary and scores like a shell, where the head/tail boilerplate
    doesn't. Two windows at the injection sites, not the body shredded.
    (`test/run train` prints all of these; drop the head/tail block in
    `mlFeatureUnits()` for the lower-false-positive, function-only variant.)
- **Missing a shell is worse than a false positive** (owner's call), so the
  thresholds are tuned for recall, not precision. Held out (389k benign / 1,581
  shells), vs the earlier 0.9/0.6 point:
  - `ML_THRESHOLD` 0.9 -> 0.8 and `ML_FLOOR` 0.6 -> 0.4: the model alone reaches
    the bar sooner and starts adding points sooner. +26 standalone shells (43
    missed -> 17), injected 85.4% -> 90.1%, for benign false positives 1.4% ->
    2.0%. `test/run train`'s floor sweep brackets 0.4 (0.3-0.6).
  - `pcntl_exec` promoted to Critical RCE (replaces the process with a program).
    `@com_exec` added -- `new COM('WScript.Shell')` / `new DOTNET(…)` is Windows
    OLE command execution. A critical token needs BOTH the 10.0 weight tier and
    the `critical` role; adding only the role scores it 1.0 (the `@com_exec` bug,
    fixed).
  - `assert` runs code only when its argument is a string or a request value, so
    it is Critical through the `@assert_exec` structural signal
    (`assert("…")` / `assert($_POST[..])`), not as a bare token. Measured the
    split first: of benign `assert` calls 536 are `assert($expr)` test
    assertions and 8 pass a string; of shell `assert` calls 23 of 34 pass a
    string or superglobal. Blanket-critical `assert` cost 1.4pt of benign false
    positives for the same catches; the gate keeps the catches and gives the
    false positives back (held out, 2.8% -> 2.0%; rules-only FP back to 1.0%).
    A plain `assert($x === 3)` keeps its routine weight.
  - PHP 4's `$HTTP_*_VARS` / `$HTTP_RAW_POST_DATA` / `$HTTP_POST_FILES` count as
    request input/upload like their `$_` forms (the scanner supports PHP 4.3).
  - Trainer `--l2` 0.001 -> 0.0005 (the model was over-regularized). Held out at
    the same 0.8/0.4: benign false positives 2.0% -> 1.9% (7,649 -> 7,417),
    injected 89.8% -> 91.1%, standalone unchanged at 17 missed -- but not the
    same 17: `cbe9ea…` (tanjiti) and `php-shell-file_put_contents.php`
    (lcatro) drop out, two encoded `xorro` shells come in. Shipped as an owner
    call on that swap. No l2 between 0.0005 and 0.001 keeps every shell:
    `cbe9ea…` drops at any value below 0.001, and 0.0007/0.0008 give no FP
    gain. Lower still (0.0001: 1.7%) costs standalone shells outright.
  - ML points no longer stop at 10: they reach `CRITICAL_SCORE` at `ML_CRITICAL`
    0.95 and keep the same slope (17.3 at 1.0). The rule score grows with file
    size (one weight per matched needle), so a big CMS file out-scored a small
    shell the model was sure of, and ML alone could never make critical. Held
    out: critical holds 95.9% of standalone shells instead of 72.9% (injected
    72.8% -> 84.9%), benign critical 0.3% -> 0.6%. Below `ML_THRESHOLD` nothing
    moved, so the anomaly set is identical. Swept 0.90-0.97: past 0.95 each
    extra shell costs ~36 benign files in critical.
  - Measured and *not* shipped, because each lost shells or saved nothing:
    requiring a sub-unit to carry its own critical token before its ML score
    counts (FP ~1.3%, but ~200 injected shells — the per-unit score exists for
    shells the rules can't see); raising only `ML_UNIT_FLOOR` (~23 injected
    shells per ~800 FP); stopping uncorroborated files (no critical, upload,
    password or 2+ recon) from flagging on rule score (0 shells lost, but held
    out FP stayed 2.0%: the statistical triggers flag those files anyway).
    Below ~1.9% combined FP, every knob found so far trades specific shells.
  - The opposite trade (a false-positive pass: cap unbacked execution calls,
    gate the entropy trigger on a non-routine token, raise `ML_UNIT_FLOOR` to
    0.95) was built and measured -- combined FP 1.4% -> 0.55% -- but *not*
    shipped, because each part missed shells. Revisit only if the owner reverses
    the call. The measured knobs are above and in git history.
  - Trap worth remembering: training scores each corpus alone, so packed shells
    sit among packed shells and the entropy z-trigger *looks* useless (0 unique
    catches). Scored against each benign site's distribution it catches ~18% of
    the shells the rules miss. Check a population-dependent signal that way
    before dropping it. Same for the suspicious-folder bonus: shell corpora
    don't sit in deployment paths, so the data can't measure it.
- **not-shells.txt** (`test/corpora/`): files inside the webshell collections
  that aren't shells (bundled libraries, config, `phpinfo()` pages, include
  stubs, toolkit UI/data/asset components, empty files), matched by MD5.
  Dropped from training and the benchmark. Add to it, don't relabel, when a
  collection carries a non-shell.
  - A file is a non-shell only when it is positively, by inspection, one of
    those things -- **never** because a capability scan found "nothing". Those
    are opposite claims: the positive corpora are full of heavily obfuscated
    shells (YAK-Pro-encoded, `array_walk_recursive`/`array_intersect_ukey`
    callback dispatch, `mb_eregi_replace('...','e')`, `"${eval(...)}"` string
    interpolation, COM objects, SQL/MOF shells) whose capability is invisible
    to a scanner -- and those are exactly the hard cases the detector exists to
    catch, so excluding them would both corrupt ground truth and fake the
    detection rate. When unsure, keep it labelled a shell. An inertness scan
    can *suggest* candidates, but every entry here was confirmed by reading the
    file, not by the scan alone.
- A hashed ML feature for identifier-like string literals (`sv:assert`) was
  tried for the string-named-function blind spot and reverted: +0.8 pt on
  injected shells didn't earn the `ML_FEATURE_VERSION` bump (older installs
  then refuse the model). `@callback_exec` covers the common case in the rules
  at no feature churn. The injected blind spot is closed by per-unit scoring.
- **Vendor checksums** (`checksumVerified()`, `checksums.txt`, `test/run
  checksums`): a file byte-identical to an official release's file at that
  path is VERIFIED, its score held down, unless the blacklist or MHR names it. The
  owner's alternative idea, shipping the trainer to learn on the live site, was
  rejected: the site can't label its own files, so a shell already there (or
  look-alikes an attacker plants) would be learned as normal. Decisions:
  - **Mark, don't hide.** Unlike the whitelist, a verified file is still
    analysed and listed, with its tokens and a badge naming the release: an
    official release can itself be backdoored, and the badge makes that
    checkable.
  - **In the score, not around it.** `scoreRows()` saturates a verified
    file's threat score below `VERIFIED_MAX` (half the anomaly bar):
    `4 s / (s + 4)` of its content score `s` (kept as `contentScore`), before
    the blacklist/MHR lift to 100. Every consumer of `threatScore` (flags,
    critical, sorting, charts, copy) then follows with no special case; only
    the statistical triggers in `flagAnomalies()` need `!d.verified`. A first
    version kept the full score and special-cased seven consumers: verified
    files still sorted to the top, and the badge hid the row's tokens. A
    multiplier doesn't bound it (×0.1 still left 100 listed files at or over
    8; scores reach 466), a subtraction even less.
  - **MD5**, because PHP 4.3 has no `hash()`. Matching an existing file's MD5
    needs a second preimage, out of reach; MD5 collisions need both files made
    by the attacker, which doesn't help here.
  - **Path-bound.** WordPress core/plugins by path inside the install;
    `checksums.txt` by path suffix at a directory boundary (`/src/A.php`
    matches `…/vendor/acme/lib/src/A.php`, not `…/xsrc/A.php`), so a vendor
    tool copied to another place isn't vouched for there.
  - **checksums.txt lists only release files that are flagged or score >= 4**
    (14,217 files, 1.24 MB). All release files would be ~398k / 38 MB,
    too much to download per scan; >= 4 instead of >= 8 leaves margin for a
    real site's statistics. Rebuild after a model or rule change. An MD5 that
    also occurs in a webshell corpus or blacklist.txt is never listed (163
    release files are, e.g. libraries bundled in shell kits).
  - Only WordPress publishes per-file checksums (core and wordpress.org
    plugins; no themes). Joomla publishes package hashes only, Drupal and
    Magento nothing per file, so the rest come from our own corpora.
  - **Sources are data** (`$checksumSources`): root marker, version/locale
    readers (a file pattern or a plugin-style header), manifest URL template,
    label. JSON is read with `json_decode()` behind `functionAvailable()`,
    as MHR does: these APIs are HTTPS-only, which legacy PHP without
    `json_decode` can't do either. checksums.txt is looked up in its text
    (`strpos` of the MD5), not parsed into an array.
  - The WordPress endpoints were unreachable from the development container
    (egress-blocked), so test/php/selfcheck.php points the URL settings at
    local files in the documented formats (escaped slashes, md5 lists, upper
    case, a locale falling back to en_US).
- **Scan progress:** each batch is listed as it arrives, every file scored on
  its own (`analyzeData([file])`, whose statistics are neutral), and the bar
  counts files that came back. The statistics need the whole scan, so the
  final `reanalyze()` flags outliers and redraws the table sorted. A full
  rescore and redraw every 3 s used to block the page and the next request,
  so the list and the bar trailed what had arrived.
- After making important decision dump it here

## Known limits

- **Charts draw every file.** They are off until opened, but on a site of
  hundreds of thousands of files the dots cost time and memory; sample or
  cap them if that becomes a problem.

## Style

Match the surrounding code: 4-space PHP indent, docblocks on functions,
comments that explain *why*. Keep diffs minimal and don't add abstractions,
files or dependencies that the task doesn't need.
