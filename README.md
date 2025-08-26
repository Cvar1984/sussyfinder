# SussyFinder
[![CodeFactor](https://www.codefactor.io/repository/github/cvar1984/sussyfinder/badge)](https://www.codefactor.io/repository/github/cvar1984/sussyfinder)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)

PHP web application that scans a directory for files with specific extensions (e.g., PHP scripts) and checks for suspicious tokens or patterns within the files.

The application uses various PHP functions and techniques to achieve this, including recursive directory scanning, file token extraction, and token comparison.

This tool is designed to help identify potentially malicious PHP files in a web server environment, but it should be used with caution as it may produce false positives and has the capability to delete files.
## Requirements
- PHP4/PHP5/PHP7/PHP8
- VirusTotal APIKey (Optional)
## Features
- token based comparison (ignore some obfuscation technique)
- support "<?" and "<%" notations
- md5 hash based comparison (whitelist & blacklist)
- recent times sorted result
- highlight result by color
- copy paste result

![ss](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/demo.jpg)
![profile](https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/profile.png)
>clone webshells submodule for testing

## Whitelist & blacklist
Whitelist system exist to skip the program from scanning whitelisted files to speed up the whole thing.

Whitelist hash i provide is harvested from common frameworks and libraries, its up to you to trust it or no.

Blacklist system exist also to speed up the scanning progress and make it easier to spot the malware.

please provide the source files if you want to make pr to add your own hash data.