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
>clone webshells submodule for testing

## Whitelist & blacklist
Whitelist system exist to skip the program from scanning whitelisted files to speed up the whole thing.

Whitelist hash i provide is harvested from common frameworks and libraries, its up to you to trust it or no.

Blacklist system exist also to speed up the scanning progress and make it easier to spot the malware.

please provide the source files if you want to make pr to add your own hash data.

## Breakdown
Here's a breakdown of the code:

1.Helper Functions:
* `recursiveScan`: Recursively scans a directory and returns an array of readable and non-readable files.
* `sortByLastModified`: Sorts an array of files by their last modified time.
* `getSortedByTime`: Combines recursive scanning and sorting by modified time.
* `getSortedByExtension`: Filters files by specified extensions and sorts them.
* `getFileTokens`: Tokenizes the content of a file and returns an array of tokens.
* `inStringArray`: Searches for a string in an array (case-insensitive).
* `compareTokens`: Compares two arrays of tokens and returns matches.
* `urlFileArray`: Fetches content from a URL and returns it as an array.
* `vTotalCheckHash`: Checks a file hash against the VirusTotal API.

2.Configuration Arrays:
* `$APIKey`: An array to store VirusTotal API keys.
* `$ext`: An array of file extensions to scan.
* `$tokenNeedles`: An array of potentially suspicious PHP functions and keywords to look for.

3.Scanning Logic:
* When the form is submitted, it scans the specified directory.
* It checks each file against the whitelist, blacklist, and VirusTotal API.
* It also performs token analysis to look for suspicious functions.
* The results are displayed in an HTML table, with different colors indicating various levels of suspicion.

4.File Operations:
* The script can delete files that match the blacklist or are identified as malicious by VirusTotal.
