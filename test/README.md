# SussyFinder tests

Everything runs through one command, `test/run`. Run it with no arguments to see the commands, or `test/run <command> --help` for a command's options.

```sh
test/run setup            # fetch the benchmark samples (once)
test/run all              # unit tests, benchmark and browser test: run before a commit
```

## Commands

| Command | What it does | Needs |
| ------- | ------------ | ----- |
| `test/run setup` | Fetches the benchmark samples. `--all` fetches every sample (for `train`), `--phtest` fetches the legacy PHP builds, and `--docker` pulls the PHP images `matrix` uses | git, Docker for `--docker` |
| `test/run unit` | Unit tests, in seconds. In PHP: the detectors on snippets, the directory listing, model-file checks. In JS: the ML pipeline's pieces and the scoring block's threshold handling | php |
| `test/run bench` | Detection benchmark on the local php: the PHP self-check, then detection and false-positive rates on the benchmark samples. `--list` names misses and false positives | php, benchmark samples |
| `test/run matrix` | `bench` plus a page/AJAX check on every PHP version × php.ini profile, in Docker, ending in one table | Docker, benchmark samples |
| `test/run ui` | The page in headless Chrome with real mouse and keyboard events | php, Chrome or Chromium (`CHROME_BIN`) |
| `test/run train` | Trains and cross-validates the ML model; `--write` updates `ml-model.json` | php, every sample (`setup --all`) |
| `test/run all` | `unit`, `bench` and `ui` (with `--matrix`, `matrix` too), with a summary | as above |

Every command exits non-zero on failure and rejects unknown options. Temporary files go to the system temp directory and are removed when the command ends, including on Ctrl+C.

## Layout

```
test/
├── run                 the entry point
├── README.md           this index
├── commands/           one file per command; each declares its name, help, options and run()
│   ├── index.js        the command list, in the order test/run shows it
│   ├── setup.js  unit.js  bench.js  matrix.js  ui.js  train.js  all.js
├── lib/                what the commands share; no command-line handling
│   ├── cli.js          parses test/run's arguments, prints help, cleans up
│   ├── paths.js        where everything is
│   ├── cleanup.js      temp directories and exit handlers
│   ├── util.js         hashing, grouping, rates
│   ├── php.js          PHP jobs: prelude, resume after a PHP crash, row parsing
│   ├── scanner.js      main.php: detection policy, scoring block in a vm, constants, model
│   ├── corpora.js      the sample submodules and how a sample is labelled
│   ├── selfcheck.js    the PHP-side unit checks (unit, and matrix on every version)
│   ├── benchmark.js    extraction + scoring + rates per target (bench, matrix)
│   ├── targets.js      local php or Docker containers, php.ini profiles
│   ├── webcheck.js     the page/AJAX check inside a container
│   ├── browser.js      headless Chrome over the DevTools protocol (ui)
│   └── ml.js           the ML pipeline: features, samples, folds, training, quantization
├── php/                PHP-side jobs that main.php is included into (PHP 4.3-safe)
│   ├── extract.php     feature rows for every file in some directories
│   └── selfcheck.php   detector snippets, listing fixture, model files
├── corpora/            sample submodules (not in a normal clone; see setup)
│   ├── positive/       webshell collections: label "shell"
│   ├── noise/          frameworks and CMSs across many releases: label "benign"
│   └── .rows/          cached feature rows (git-ignored)
└── PHTest/             Docker builds of legacy PHP versions (submodule)
```

## How the pieces fit

- **One copy of the scanner.** Every test uses the real `main.php`. The PHP jobs include it with `define('SUSSY_LIB', true)`, which stops it before it serves anything. The JS tests run its client-side scoring block, between the `// --- Client-side threat scoring` markers, in a Node `vm`.
- **The PHP self-check** (`lib/selfcheck.js` with `php/selfcheck.php`) runs under `unit` on the local php and under `matrix` on every container, so every PHP version is held to the same expectations.
- **The benchmark** (`lib/benchmark.js`) is the same code for `bench` and `matrix`. Only the target differs: the local php, or containers that mount the repository read-only, so a blacklist hit can't delete samples.
- **Samples are labelled by folder.** `positive/` is a shell and `noise/` is legitimate code. Extra keys in `.gitmodules` add `family` (corpora held out together in cross-validation), `subdir` and `benchmark = true` (the quick set that `bench`, `matrix` and `ui` use).
- **Feature rows are cached** per corpus commit in `corpora/.rows/`. They are re-extracted only when `main.php`'s extractor or `php/extract.php` changes.

## Adding things

- **A command:** add `commands/<name>.js` exporting `{ name, summary, about, options, examples, run(args) }`, where `run` returns an exit code, then list it in `commands/index.js`.
- **A detector case:** add `[snippet, must match, must not match]` to `CASES` in `lib/selfcheck.js`. It then runs on the local php and on every PHP version.
- **A JS unit test:** add a `test(name, fn)` in `commands/unit.js`.
- **A browser check:** add a scenario to `commands/ui.js`, using `check(name, ok, info)`.
- **A php.ini profile:** add it to `PROFILES` in `lib/targets.js`.
