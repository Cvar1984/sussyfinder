# SussyFinder
[![CodeFactor](https://www.codefactor.io/repository/github/cvar1984/sussyfinder/badge)](https://www.codefactor.io/repository/github/cvar1984/sussyfinder)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)

PHP web application that scans a directory for files with specific extensions (e.g., PHP scripts) and performs in-depth analysis to detect potentially malicious code.

It combines token‑based pattern matching, statistical anomaly detection (Shannon entropy, Z‑scores, residual analysis), and MD5 hash whitelist/blacklisting to help identify suspicious files in a web server environment.

> **⚠️ Use with caution** – this tool can delete files identified as blacklisted. Always review flagged files before taking action.

## Features
- **Recursive directory scanning** with symlink loop protection
- **Token‑based detection** – scans PHP tokens for known obfuscation, shell execution, file I/O, and credential‑related functions
- **MD5 hash whitelist & blacklist** – skip known‑good files (e.g., from common frameworks) and auto‑delete known‑bad files
- **Shannon entropy calculation** – detects heavily obfuscated or encoded content
- **Client‑side statistical analysis** – computes Z‑scores (size, tokens, suspicious token count, entropy) and residuals to flag outliers
- **Interactive web interface** with:
  - Sort by modification time, suspicious token count, Z‑score, or residual
  - Filter to show only anomalies
  - One‑click copy of results (with full details)
  - Clickable file paths to copy MD5 hash
- **Color‑coded output** – highlights blacklisted, unreadable, and suspicious files
- **Self‑contained** – single PHP file, no external dependencies

## Requirements
- PHP 4.3 / 5.x / 7.x / 8.x (with `token_get_all` support)
- Web server (Apache, Nginx, etc.) or PHP built‑in server
- Internet access (optional) to fetch whitelist/blacklist from GitHub – can be disabled via constants

## Usage
1. Place `index.php` (or whatever you name it) in a web‑accessible directory.
2. Access the file through your browser.
3. Enter the absolute or relative path of the directory you wish to scan.
4. Click **SEARCH** – the tool will recursively scan and analyse all files matching the configured patterns (`.php`, `.inc`, `.htaccess`, etc.).
5. Review the results table – files with anomalies are marked with ⚠️.
6. Use the control bar to sort, filter, or copy the results.
   - Blacklisted files are **automatically deleted** – ensure you trust the blacklist source.
7. Click on any file path to copy its MD5 hash to the clipboard.

## Whitelist & Blacklist
- **Whitelist** – MD5 sums of known‑safe files (e.g., from popular frameworks). These files are skipped entirely to speed up scanning.
- **Blacklist** – MD5 sums of known malware. Files matching these are **automatically unlinked** (deleted) and flagged in the output.

By default, both lists are fetched from:
- `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt`
- `https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt`

You can disable fetching by setting the constants `_WHITELIST_` or `_BLACKLIST_` to `false` in the code.

> **Note:** The provided whitelist is harvested from common frameworks and libraries. It is up to you to trust or modify it. For blacklist contributions, please provide source files when creating a pull request.

## Screenshots
![Demo](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo.png)
![Profile](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/profile.png)

> Clone the webshells submodule for testing purposes.

## Security & Disclaimer
This tool is intended for system administrators and security researchers. It performs **aggressive** file operations (deletion) and may produce false positives. Always audit flagged files before any automatic action. The author is not responsible for any data loss or damage caused by the use of this software.

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change. Please ensure tests are updated appropriately.

## License
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html)