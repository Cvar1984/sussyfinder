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
  is_blacklisted, is_htaccess, duplicate_of, error, is_unreadable`.
  Stat calls (`filectime`/`fileowner`) happen **before** a blacklist unlink.
- **Detection primitives:** `getFileTokens` (token_get_all, minus literal text
  inside `"..."`, backticks and heredocs: old tokenizers emit that text as
  `T_STRING`), `tokenTextSet`
  (ignores string/HTML/comment content and method names after `->` / `::` /
  `function`; strips a leading `\`), `compareTokens` (isset lookups against the
  `$tokenNeedles` weight map), `findStructuralSignals` (pseudo-tokens, below),
  `shannonEntropy` (whole-file bytes). `codeTokens()` walks the tokens once
  and `analyzeContent()` hands the result to all of them.
- **Pseudo-tokens** are prefixed `@`, which no real PHP token can match:
  `@input_call` `$_GET['a']()`, `@preg_e`, `@concat_name` (name hidden in a
  string; the recovered name is added too), `@halt_payload`, `@dyn_call`,
  `@long_line`. Their weights live in `$tokenNeedles` next to real tokens.
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
- **AJAX:** POST `ajax_action` = `scan` | `process` | `mhr_check` | `mhr_unlink`.
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
  with `jsonEncode()` (UTF-8-safe), so the body is never empty.
- **`mhr_unlink`** deletes only files whose *current* md5 MHR confirms in that
  same request. Never make it trust the browser's path list.
- **Listing** (`getSortedByPattern` → `recursiveScan`): `$pattern` is one
  complete regex matched against the file name (validated before use).
  Regular files only (a FIFO would hang `md5_file`). Symlinked files are
  listed; symlinked dirs are followed only inside the scan root. Anything
  unscannable is reported with `trigger_error()`, not skipped silently.
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
  returns the status and body. Hash lists are kept in the scan's own session
  (`hashList()`), never taken from the browser.
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
- After making important decision dump it here

## Style

Match the surrounding code: 4-space PHP indent, docblocks on functions,
comments that explain *why*. Keep diffs minimal and don't add abstractions,
files or dependencies that the task doesn't need.
