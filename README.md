# SussyFinder
[![CodeFactor](https://www.codefactor.io/repository/github/cvar1984/sussyfinder/badge)](https://www.codefactor.io/repository/github/cvar1984/sussyfinder)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://makeapullrequest.com)

PHP web application that scans a directory for files with specific extensions (e.g., PHP scripts) and checks for suspicious tokens or patterns within the files. The application uses various PHP functions and techniques to achieve this, including recursive directory scanning, file token extraction, and token comparison.
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

1. The code starts by defining various arrays, including 
- `$ext` (file extensions to scan)
- `$tokenNeedles` (suspicious tokens to look for)
- `$whitelistMD5Sums` (MD5 sums of files to skip)
- and `$blacklistMD5Sums` (MD5 sums of files to remove).
2. The code then defines several functions, including
- `recursiveScan` (recursively scans a directory for files)
- `sortByLastModified` (sorts an array of files by their last modified time)
- `getSortedByTime` (recursively lists files by descending modified time)
- `getSortedByExtension` (recursively lists files by array of extensions)
- `getFileTokens` (extracts lowercase tokens from a file)
- `inStringArray` (checks if a needle exists in an array of strings)
- `compareTokens` (compares tokens and returns matched tokens)
- `urlFileArray` (fetches an array of strings from a URL), and a HTML template for the web application.
3. The code then initializes the `$ext` array with various PHP file extensions.
4. The code defines the `$tokenNeedles` array with suspicious tokens or patterns to look for within the files.
5. The code fetches the MD5 sums of files to skip and files to remove from URLs using the `urlFileArray` function.
6. The code then defines the HTML template for the web application, including a form for users to input the directory to scan.
7. Inside the form, the code checks if the user has submitted the form. If so, it retrieves the directory path from the form input, calls the `getSortedByExtension` function to get the sorted files, and then iterates over the files to check for suspicious tokens or patterns.
8. If a suspicious token or pattern is found, the code displays a message indicating the file path and the suspicious tokens.
9. The code also includes a button to copy the results to the clipboard.


Overall, the selected code is a PHP web application that scans a directory for suspicious PHP files and checks for suspicious tokens or patterns within the files. The application uses various PHP functions and techniques to achieve this, including recursive directory scanning, file token extraction, and token comparison.
