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
| `test/run.js` | The test suite: detector self-checks + detection benchmark on the local PHP, or with `--php all` on every PHTest version plus a page/AJAX smoke test. |
| `test/webshells`, `test/WordPress`, `test/laravel` | Test corpora: malicious vs benign. Their working trees are dirty on purpose; never commit or "clean" them. |
| `PHTest/` | Separate git repo: Docker images for PHP 4.1.2 … 8.5.6. See `PHTest/README.md`. |

## Hard rules

1. **PHP4 syntax in all PHP.** `array(...)` never `[...]`; no closures, `fn`,
   `??`, `?:`, `?->`, namespaces, type hints, etc. Plain `cond ? a : b` is
   fine. Ignore IDE hints suggesting modern syntax.
2. **Runtime floor is PHP 4.3** (4.1/4.2 lack `token_get_all`). Any function
   newer than 4.3 must be guarded (`function_exists` / `isWorking()`) or given
   a fallback, e.g. the `json_encode` fallback near the top of `main.php`.
   Hosts often set `disable_functions`, so call risky builtins through
   `isWorking()`. Tokenizer constants newer than PHP 4 (`T_DOC_COMMENT`,
   `T_NULLSAFE_OBJECT_OPERATOR`) are only used via `defined()` + `constant()`.
3. **No backward-compat shims.** When a field, format or signature changes,
   change every reader and writer in the same edit. Never accept "old or new".
   Client JS and server PHP ship together in one file, so there is no one to
   stay compatible with.
4. **`main-cli.php` is parked.** Don't port `main.php` changes to it and don't
   add cross-file sync checks unless the maintainer revives it.
5. **Never let the scanner delete test data.** A blacklist hit `unlink()`s the
   file. Run the web UI / AJAX against the corpora only with the repo mounted
   read-only (as `test/run.js --php` does). Never run `main-cli.php` on `test/`.
6. **Measure detection changes.** Any change to needles, weights, signals or
   anomaly rules gets a before/after `node test/run.js` run, reported in
   the summary; touching the tokenizer helpers also gets `--php all`. Don't
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
  `shannonEntropy` (whole-file bytes).
- **Pseudo-tokens** are prefixed `@`, which no real PHP token can match:
  `@input_call` `$_GET['a']()`, `@preg_e`, `@concat_name` (name hidden in a
  string; the recovered name is added too), `@halt_payload`, `@dyn_call`,
  `@long_line`. Their weights live in `$tokenNeedles` next to real tokens.
- **Client** scoring lives between `// --- Client-side threat scoring` and
  `// --- End client-side threat scoring ---`. `test/run.js` executes exactly
  that slice, so keep it self-contained (no DOM) and keep the markers.
  `HIGH_ENTROPY` there is the single entropy threshold used everywhere.
- **`define('SUSSY_LIB', true); include 'main.php';`** stops right after
  `$tokenNeedles` (before list downloads, AJAX and HTML). The tests rely on it.
- **AJAX:** POST `ajax_action` = `scan` | `process` | `mhr_check` | `mhr_unlink`.
  `process` takes `paths` and `seen_hashes` as **NUL-separated strings**
  (`postList()`), not arrays or JSON. One field stays under `max_input_vars`,
  NUL can't occur in a path, and no `json_decode` is needed on old PHP.
  Responses go through `ajaxRespond()`, which folds in captured PHP warnings.
- **Downloads** (`urlFileArray`, `mhrSubmitHashes`) try cURL, then
  `file_get_contents`, then `file()`. Treat anything but a non-empty
  string/array as failure: PHP 4.3's `file_get_contents` returns NULL, not false.
- **MHR** (Team Cymru) needs PHP 5.2+ (`json_decode`) and HTTPS; on older PHP it
  returns a clear error. A `json_decode` fallback was deliberately not added:
  legacy builds have no HTTPS, so it could never run.
- **VT button** on each row opens the VirusTotal report for the file's MD5.

## Testing

```sh
php -l main.php                       # syntax (also run with a PHP 4 binary via PHTest if you touched PHP)
node test/run.js                      # local php: detector self-checks + detection rates; exits 1 on failure
node test/run.js --list               # + missed webshells and false positives
node test/run.js --tokens             # + per-token webshell vs benign counts, for tuning weights
node test/run.js --php all            # every PHTest version (docker + built images, ~5 min) + page/AJAX smoke test
node test/run.js --php 4.3.11,8.5.6   # just those versions
```

Baseline (threshold 3.5, local PHP and every container alike): **anomaly
167/202 detected, 18/1927 false positives; score ≥ 8: 161/202, 10 FP;
score ≥ 15: 151/202, 1 FP.**
Expected `--php all` result: 4.1.2/4.2.3 fail (below the floor, reported as
n/a, not a failure). 4.3.0 through 8.5.6 pass all self-checks and the web
check. Known, accepted differences:
- PHP 4.3.0's tokenizer segfaults on ~94 modern WordPress files. The runner
  skips them and resumes, like the UI's one-by-one retry. 4.3.0 also labels
  AJAX replies text/html (a bug in that PHP build), which is harmless.
- On 4.3.x/5.0.x, 5 WordPress files gain `@dyn_call`: they contain nowdocs
  (`<<<'EOT'`, PHP 5.3+), which old tokenizers can't parse. Such files can't
  run on those hosts anyway.
- `total_tokens` differs slightly on old PHP (tokenizer differences).

`run.js` zeroes mtime/ctime because the corpora were copied at different
times (the webshells keep 2024 mtimes) and would otherwise be "detected" for
free. So the ctime-gap, mtime and rare-owner signals are **not** measured by
the bench, and neither is the `uploads/` rule (no corpus file lives there).

## Decisions already made (with evidence), so don't redo them

- Entropy is whole-file bytes, threshold 5.5: 98/202 webshells vs 1/1927
  benign. "Longest string literal" entropy was tried and was worse at useful
  thresholds.
- Z-scores are median/MAD (Iglewicz & Hoaglin), with a mean-absolute-deviation
  fallback when MAD = 0. The ctime−mtime gap has a 1-day scale floor. Entropy
  z is one-sided (high side only).
- `zSize` and `zSusp` are computed and shown but **not** anomaly triggers: each
  caught 0 unique webshells and added false positives.
- Removed signal `@string_heavy` (23 webshells vs 99 benign).
- `preg_replace`, `call_user_func(_array)`, `register_shutdown/tick_function`
  are weight 0.1: 0 webshells vs 90+ benign files; the dangerous `/e` form is
  scored as `@preg_e`.
- "User input + `@dyn_call`" is **not** treated as code execution: WordPress
  uses `$callback(...)` identically. Only the direct `$_GET[...](...)` shape
  (`@input_call`) is critical. Real taint tracking would be the next step:
  track `$x = $_GET[...]` then `$x(...)` in `findStructuralSignals`, and
  measure it with the bench.
- An AST parser (npm `php-parser`, nikic/PHP-Parser) was rejected: it would
  force shipping full file sources to the browser or require PHP 7+, would
  fail on malformed/legacy malware, and would recover only ~1–3 of the
  current misses.
- Short open tags (`<?if(...)`) are rewritten to `<?php ` before tokenizing,
  so detection doesn't depend on the scanning host's `short_open_tag` (it did:
  a local run missed `shell_exec` in NCC-Shell.php that a container caught).
  `<?=`, `<?php` and `<?xml` are left alone.
- About 15 of the remaining misses are ASP/JSP/Perl shells saved as `.php`;
  PHP tokenization can't see them.

## Style

Match the surrounding code: 4-space PHP indent, docblocks on functions,
comments that explain *why*. Keep diffs minimal and don't add abstractions,
files or dependencies that the task doesn't need.
