# SussyFinder

[![CodeFactor](https://www.codefactor.io/repository/github/cvar1984/sussyfinder/badge)](https://www.codefactor.io/repository/github/cvar1984/sussyfinder)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)

PHP web application that scans a directory for files with specific extensions (e.g., PHP scripts) and performs in-depth analysis to detect potentially malicious code.

It combines token-based pattern matching, statistical anomaly detection (Shannon entropy, Z-scores, residual analysis), and MD5 hash whitelist/blacklisting to help identify suspicious files in a web server environment.

> **⚠️ Use with caution** – this tool can delete files identified as blacklisted. Always review flagged files before taking action.

## Features

* **Recursive directory scanning** with symlink loop protection
* **Token-based detection** – scans PHP tokens for known obfuscation, shell execution, file I/O, and credential-related functions
* **MD5 hash whitelist & blacklist** – skip known-good files (e.g., from common frameworks) and auto-delete known-bad files
* **Shannon entropy calculation** – detects heavily obfuscated or encoded content
* **Client-side statistical analysis** – computes Z-scores (size, tokens, suspicious token count, entropy) and residuals to flag outliers
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

Shannon entropy measures the amount of information or randomness in a dataset. SussyFinder applies it to the characters contained in the extracted suspicious tokens.

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

SussyFinder gives additional weight to small PHP files with high entropy:

$$
Entropy > 5.8
$$

and

$$
Size < 20480\ \text{bytes}
$$

When both conditions are met, the threat score receives an additional bonus.

### Mean

The arithmetic mean is used as the baseline for the statistical measurements.

$$
\mu = \frac{1}{n}\sum_{i=1}^{n}x_i
$$

Where:

* $\mu$ = mean
* $x_i$ = individual observation
* $n$ = number of observations

SussyFinder calculates the mean for:

* File size
* Modification time
* Total token count
* Suspicious token count
* Shannon entropy

### Population Variance

The variance measures how far observations are distributed around the mean.

$$
\sigma^2 =
\frac{1}{n}
\sum_{i=1}^{n}(x_i-\mu)^2
$$

### Standard Deviation

Standard deviation is the square root of variance:

$$
\sigma = \sqrt{
\frac{1}{n}
\sum_{i=1}^{n}(x_i-\mu)^2
}
$$

A large standard deviation indicates that the values vary significantly across the scanned files.

### Z-Score

SussyFinder uses Z-scores to determine how far a file's characteristics are from the dataset mean.

$$
Z = \frac{x-\mu}{\sigma}
$$

Where:

* $x$ = observed value
* $\mu$ = mean
* $\sigma$ = standard deviation

The absolute value can be used to measure how unusual a value is:

$$
|Z|
$$

A larger $|Z|$ indicates a more statistically unusual observation.

SussyFinder calculates Z-scores for:

* File size
* Modification time
* Total tokens
* Suspicious token count
* Shannon entropy

The default anomaly threshold is:

$$
|Z| > 3.5
$$

This threshold can be changed through the **Z-threshold** control in the web interface.

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
| Routine operations | `include`, `fopen`, `substr`    |  $0.1$ |

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

#### Suspicious Path Bonus

If the file is located in directories such as:

* `upload`
* `cache`
* `tmp`
* `images`
* `media`

and the score is already suspicious or entropy is high:

$$
Score' = Score + 5
$$

#### High-Entropy Small File Bonus

For files smaller than 20 KiB with high entropy:

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
|Z_{suspicious}| > T
\lor
|Z_{entropy}| > T
\lor
|Z_{mtime}| > T
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
very small files with no bearing on maliciousness.

`.htaccess` files and byte-identical duplicates are shown with their own
badges/counters but no longer auto-flagged as anomalies either — a shared
Apache config file or a stock duplicate (e.g. WordPress's many identical
"Silence is golden" `index.php` stubs) isn't inherently suspicious on its
own. Only content/threat-based signals decide anomaly status.

This means the statistical analysis is used alongside deterministic security indicators rather than as the sole detection mechanism.

## Requirements

* PHP 4.3 / 5.x / 7.x / 8.x (with `token_get_all` support)
* Web server (Apache, Nginx, etc.) or PHP built-in server
* Internet access (optional) to fetch whitelist/blacklist from GitHub – can be disabled via constants

## Usage

1. Place `index.php` (or whatever you name it) in a web-accessible directory.
2. Access the file through your browser.
3. Enter the absolute or relative path of the directory you wish to scan.
4. Click **SEARCH** – the tool will recursively scan and analyse all files matching the configured patterns (`.php`, `.inc`, `.htaccess`, etc.).
5. Review the results table – files with anomalies are marked with ⚠️.
6. Use the control bar to sort, filter, or copy the results.

   * Blacklisted files are **automatically deleted** – ensure you trust the blacklist source.
7. Click on any file path to copy its MD5 hash.

## Whitelist & Blacklist

* **Whitelist** – MD5 sums of known-safe files (e.g., from popular frameworks). These files are skipped entirely to speed up scanning.
* **Blacklist** – MD5 sums of known malware. Files matching these are **automatically unlinked** (deleted) and flagged in the output.

By default, both lists are fetched from:

* `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt`
* `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt`

You can disable fetching by setting the constants `_WHITELIST_` or `_BLACKLIST_` to `false` in the code.

> **Note:** The provided whitelist is harvested from common frameworks and libraries. It is up to you to trust or modify it. For blacklist contributions, please provide source files when creating a pull request.

## Screenshots

![Demo](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo1.png)
![Demo](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo2.png)
![Profile](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/profile.png)

> Clone the webshells submodule for testing purposes.

## Security & Disclaimer

This tool is intended for system administrators and security researchers. It performs **aggressive** file operations (deletion) and may produce false positives. Always audit flagged files before any automatic action. The author is not responsible for any data loss or damage caused by the use of this software.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change. Please ensure tests are updated appropriately.

## License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)
