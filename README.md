# SussyFinder

[![CodeFactor](https://www.codefactor.io/repository/github/cvar1984/sussyfinder/badge)](https://www.codefactor.io/repository/github/cvar1984/sussyfinder)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)

PHP web application that scans a directory for files with specific extensions (e.g., PHP scripts) and performs in-depth analysis to detect potentially malicious code.

It combines token-based pattern matching, statistical anomaly detection (Shannon entropy, Z-scores, residual analysis), and MD5 hash whitelist/blacklisting to help identify suspicious files in a web server environment.

> **⚠️ Use with caution** – this tool can delete files identified as blacklisted. Always review flagged files before taking action.

## Features

* **Recursive directory scanning** with symlink loop protection; symlinked directories leading outside the scanned directory are reported, not followed, and directories that can't be listed are reported instead of skipped silently
* **Token-based detection** – scans PHP tokens for known obfuscation, shell execution, file I/O, and credential-related functions (method names like `$pdo->exec()` and text inside strings/comments are ignored)
* **Structural detection** – catches what name matching can't: calls through variables or superglobals (`$_GET['a']($_GET['b'])`), function names hidden in strings (`'ba'.'se64_decode'`, `"\x73ystem"`), `preg_replace` with `/e`, backtick shell execution, payloads after `__halt_compiler()`, and giant single-line blobs
* **MD5 hash whitelist & blacklist** – skip known-good files (e.g., from common frameworks) and auto-delete known-bad files
* **Shannon entropy calculation** – per-file byte entropy detects heavily obfuscated or encoded content
* **Client-side statistical analysis** – computes robust (median/MAD) Z-scores for size, mtime, tokens, suspicious token count, entropy and the ctime–mtime gap, plus residuals and file-owner rarity, to flag outliers
* **Interactive web interface** with:

  * Sort by modification time, suspicious token count, Z-score, or residual
  * Filter to show only anomalies
  * One-click copy of results (with full details)
  * Clickable file paths to copy MD5 hash
* **Color-coded output** – highlights blacklisted, unreadable, and suspicious files
* **Self-contained** – single PHP file, no external dependencies

## Statistical Analysis

SussyFinder uses several statistical techniques to identify files whose characteristics differ significantly from the rest of the scanned dataset.

### Shannon Entropy

Shannon entropy measures the amount of information or randomness in a dataset. SussyFinder applies it to the raw bytes of each file (computed server-side).

The entropy is calculated as:

$$
H(X) = -\sum_{i=1}^{n} p(x_i)\log_2 p(x_i)
$$

Where:

* $H(X)$ = Shannon entropy
* $p(x_i)$ = probability of symbol $x_i$
* $n$ = number of unique symbols

The probability of each symbol is:

$$
p(x_i) = \frac{c_i}{N}
$$

Where:

* $c_i$ = number of occurrences of symbol $x_i$
* $N$ = total number of characters

Higher entropy indicates a more diverse and less predictable character distribution, which can be useful for identifying encoded or obfuscated content.

For example:

| Data                | Approximate Entropy |
| ------------------- | ------------------: |
| `AAAAAA`            |                 $0$ |
| `ABCDEF`            |      $\approx 2.58$ |
| Random/encoded data |              Higher |

Plain PHP source sits around 4.5–5.2 bits/byte. SussyFinder treats a file as high-entropy above:

$$
Entropy > 5.5
$$

On the bundled test corpus this threshold matches 98 of 202 webshells and 1 of 1927 legitimate WordPress/Laravel files.

### Median and MAD

Mean and standard deviation are pulled toward the very outliers being hunted (and toward huge vendor files), which lets them hide. SussyFinder uses the median and the median absolute deviation (MAD) instead:

$$
\tilde{x} = \operatorname{median}(x_1, \dots, x_n)
\qquad
MAD = \operatorname{median}(|x_i - \tilde{x}|)
$$

The spread is scaled so it matches a standard deviation on normally distributed data:

$$
s = 1.4826 \times MAD
$$

When more than half the values tie (MAD = 0, e.g. most files match no suspicious tokens), the mean absolute deviation is used instead:

$$
s = 1.253314 \times \frac{1}{n}\sum_{i=1}^{n}|x_i - \tilde{x}|
$$

### Z-Score

SussyFinder uses robust (modified) Z-scores to determine how far a file's characteristics are from the rest of the dataset (Iglewicz & Hoaglin):

$$
Z = \frac{x-\tilde{x}}{s}
$$

Where:

* $x$ = observed value
* $\tilde{x}$ = median
* $s$ = scaled spread from above

SussyFinder calculates Z-scores for:

* File size
* Modification time
* Total tokens
* Suspicious token count
* Shannon entropy
* ctime − mtime gap: attackers backdate mtime with `touch`, but can't set ctime that way, so a planted file's gap stands out from its neighbours'. Gaps under a day (chmod, in-place edits) are ignored by flooring $s$ at 86400 seconds.

The default anomaly threshold is:

$$
Z > 3.5
$$

This threshold can be changed through the **Z-threshold** control in the web interface.

### File Owner Rarity

A file owned by a user who owns less than 5% of the scanned files (e.g. the web-server user among FTP-deployed files) was probably written by the application, not deployed. With at least 20 files scanned, such files are marked **RARE** and flagged.

### Residual Analysis

Residual analysis compares the observed suspicious-token count with the number that would be expected based on the average relationship between suspicious tokens and total tokens.

First, the average suspicious-token ratio is calculated:

$$
r =
\frac{\overline{S}}{\overline{T}}
$$

Where:

* $S$ = suspicious token count
* $T$ = total token count
* $r$ = average suspicious-token ratio

For each file, the expected suspicious-token count is:

$$
E(S_i) = T_i \times r
$$

The residual is then:

$$
R_i = S_i - E(S_i)
$$

Where:

* $R_i$ = residual
* $S_i$ = observed suspicious-token count
* $E(S_i)$ = expected suspicious-token count

A positive residual indicates that a file contains more suspicious tokens than expected for its total token count.

SussyFinder flags a file when:

$$
R_i > 5
$$

This provides a complementary detection method to the Z-score because a file may have a suspiciously high number of tokens relative to its own size or structure even when the absolute suspicious-token count is not extremely large.

### Threat Score

SussyFinder also calculates a weighted threat score from matched tokens.

The general model is:

$$
Score =
\sum_{i=1}^{n} w_i
$$

Where:

* $w_i$ = assigned weight of a matched token
* $n$ = number of matched tokens

Example token weights include:

| Category           | Example                         | Weight |
| ------------------ | ------------------------------- | -----: |
| Critical RCE       | `eval`, `exec`, `system`        | $10.0$ |
| Obfuscation        | `base64_decode`, `gzinflate`    |  $5.0$ |
| Suspicious I/O     | `move_uploaded_file`, `$_FILES` |  $2.0$ |
| User input         | `$_GET`, `$_POST`, `$_COOKIE`   |  $0.5$ |
| Routine operations | `include`, `fopen`, `substr`    |  $0.1$ |

Structural signals appear among the matched tokens with an `@` prefix (no real PHP token can look like that):

| Signal          | Meaning                                                  | Weight |
| --------------- | -------------------------------------------------------- | -----: |
| `@input_call`   | Calls a superglobal element: `$_GET['a']($_GET['b'])`    | $10.0$ |
| `@preg_e`       | `preg_replace` with the `/e` (eval) modifier             | $10.0$ |
| `` ` ``         | Backtick operator (shell execution)                      | $10.0$ |
| `@concat_name`  | Function name hidden in a string (the name is added too) |  $5.0$ |
| `@halt_payload` | Over 1 KiB of data after `__halt_compiler()`             |  $5.0$ |
| `@dyn_call`     | Call through a variable or expression: `$f()`, `(...)()` |  $2.0$ |
| `@long_line`    | A line over 5000 characters                              |  $2.0$ |

`@input_call`, `@preg_e` and the backtick count as Critical RCE tokens; `@concat_name` and `@halt_payload` as obfuscation.

Additional multipliers are applied when combinations of suspicious behaviors are present.

#### Non-Critical Dampening

Obfuscation and suspicious-I/O tokens (e.g. `base64_decode`, `gzinflate`, `move_uploaded_file`) are common in entirely legitimate code — compression libraries, mail clients, HTTP clients, media parsers, upload handlers. On their own they're a weak signal; they matter most in combination with a real execution primitive (see the multipliers below). When a file has **no** Critical RCE token, their weight is reduced:

$$
w_i' = w_i \times 0.3
$$

This does not apply to Routine-operations-tier tokens, and has no effect once a Critical RCE token is present in the file (the combination multipliers below take over instead).

#### Critical + Obfuscation

If a file contains both a critical execution token and an obfuscation token:

$$
Score' = Score \times 2.5
$$

#### Critical + Upload Handling

If a file contains both a critical execution token and upload-related functionality:

$$
Score' = Score \times 1.8
$$

#### Critical + User Input

If a file contains both a critical execution token and a user-input token:

$$
Score' = Score \times 2.0
$$

#### Upload Folder

Upload folders hold user files, so real code in one was almost always planted. A non-`.htaccess` file with more than 5 tokens inside an `uploads` directory gets:

$$
Score' = Score + 10
$$

#### Suspicious Path Bonus

Otherwise, if the file is located in directories such as:

* `upload`
* `cache`
* `tmp`
* `images`
* `media`

and the score is already suspicious or entropy is high:

$$
Score' = Score + 5
$$

#### High-Entropy Bonus

For files with entropy above 5.5:

$$
Score' = Score + 3
$$

The final score is rounded to two decimal places.

### Anomaly Classification

A file is considered anomalous when one or more statistical or security conditions are satisfied.

Conceptually:

$$
Anomaly =
ThreatScore \geq 8
\lor
Z_{entropy} > T
\lor
|Z_{mtime}| > T
\lor
|Z_{ctime-mtime}| > T
\lor
RareOwner
\lor
Residual > 5
$$

Where:

* $T$ = configured Z-score threshold
* $\lor$ = logical OR

SussyFinder additionally treats the following as anomalies:

* Blacklisted files
* Unreadable files

File size (`Z_size`) is still computed and shown in the interface, but is not
used to decide anomaly status: tested against real webshell samples, size
alone never uniquely caught a malicious file while being the largest source
of false positives — legitimate codebases routinely contain very large or
very small files with no bearing on maliciousness. The suspicious-token
count Z-score (`Z_suspicious`) was dropped as a trigger for the same reason
(0 unique catches, 5 false positives); the weighted threat score already
covers "many suspicious tokens".

`.htaccess` files and byte-identical duplicates are shown with their own
badges/counters but no longer auto-flagged as anomalies either — a shared
Apache config file or a stock duplicate (e.g. WordPress's many identical
"Silence is golden" `index.php` stubs) isn't inherently suspicious on its
own. Only content/threat-based signals decide anomaly status.

This means the statistical analysis is used alongside deterministic security indicators rather than as the sole detection mechanism.

### Benchmark

`node test/run.js` runs the real PHP feature extraction and the real client-side scoring from `main.php` over `test/webshells` mixed with `test/WordPress` and `test/laravel`, and prints detection and false-positive rates. Timestamps are zeroed because the corpora were copied at different times, so the ctime/mtime and owner signals aren't measured there. It also runs structural-detector self-checks and fails if any of them break.

`node test/run.js --php all` does the same on every PHP version in `PHTest/` (Docker, PHP 4.1–8.5), plus a page/AJAX smoke test per version, and lists files that match differently than on the newest PHP.

* `--list` — print missed webshells and false positives
* `--tokens` — print how often each token appears in webshells vs. benign files, for tuning weights
* `--threshold 3.5` — Z-score threshold to evaluate
* `--php all` or `--php 4.3.11,8.5.6` — run on PHTest versions instead of the local `php`

## Requirements

* PHP 4.3 / 5.x / 7.x / 8.x (with `token_get_all` support); Malware Hash Registry lookups need PHP 5.2+
* Web server (Apache, Nginx, etc.) or PHP built-in server
* Internet access (optional) to fetch whitelist/blacklist from GitHub – can be disabled via constants

## Usage

1. Place `main.php` (or whatever you name it) in a web-accessible directory.
2. Access the file through your browser.
3. Enter the absolute or relative path of the directory you wish to scan.
4. Click **SEARCH** – the tool will recursively scan and analyse every file whose name matches `$pattern`: PHP-like and SSI extensions (`.php`, `.phtml`, `.inc`, `.shtml`, …), names with `php` as an inner extension (`x.php.jpg`, `shell.php.`, which Apache's `AddHandler` runs as PHP), `.htaccess`, `.user.ini` and `php.ini`.
5. Review the results table – files with anomalies are marked with ⚠️.
6. Use the control bar to sort, filter, or copy the results.

   * Blacklisted files are **automatically deleted** – ensure you trust the blacklist source.
7. Click on any file path to copy it; the 📋 icon copies its MD5 hash.
8. **MHR SCAN** looks the hashes up in Team Cymru's Malware Hash Registry and deletes files it flags. The server re-checks each file's current hash with MHR before deleting, so only confirmed matches are removed.

## Whitelist & Blacklist

* **Whitelist** – MD5 sums of known-safe files (e.g., from popular frameworks). These files are skipped entirely to speed up scanning.
* **Blacklist** – MD5 sums of known malware. Files matching these are **automatically unlinked** (deleted) and flagged in the output.

By default, both lists are fetched from:

* `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt`
* `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt`

You can disable fetching by setting the constants `_WHITELIST_` or `_BLACKLIST_` to `false` in the code. Downloads use verified TLS, because the blacklist deletes files: a host without a CA bundle gets a warning and scans without the lists rather than trusting an unverified source.

> **Note:** The provided whitelist is harvested from common frameworks and libraries. It is up to you to trust or modify it. For blacklist contributions, please provide source files when creating a pull request.

## Screenshots

![Demo](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo1.png)
![Demo](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo2.png)
![Profile](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/profile.png)

> Clone the webshells submodule for testing purposes.

## Security & Disclaimer

This tool is intended for system administrators and security researchers. It performs **aggressive** file operations (deletion) and may produce false positives. Always audit flagged files before any automatic action. The author is not responsible for any data loss or damage caused by the use of this software.

Protections built in: a CSRF check on every request (a custom header another site can't send), server-side MHR confirmation before any MHR deletion, verified TLS for list downloads, and file names treated as untrusted data in the page (an attacker who planted a file chooses its name).

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change. Please ensure tests are updated appropriately.

## License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
