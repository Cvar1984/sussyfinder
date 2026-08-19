<?php

/**
 * Written by Cvar1984 <Cvar1984@pm.me>, November 2022
 * Copyright (C) 2022 Cvar1984
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

$minute = 60;
$limit = (60 * $minute); // 60 minutes
ini_set('memory_limit', '-1');
ini_set('max_execution_time', $limit);
set_time_limit($limit);
ini_set('display_errors', 1);

define('_WHITELIST_', true);
define('_BLACKLIST_', true);

/**
 * Check if function is available
 *
 * @param callable $callback
 * @return boolean
 */
function isWorking($callback)
{
    $securityDisabled = ini_get('disable_functions');
    $securityDisabled = explode(',', $securityDisabled);

    if (in_array($callback, $securityDisabled)) {
        return false;
    }
    if (!function_exists($callback)) {
        return false;
    }
    return true;
}

if (isWorking('curl_exec')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt_array($ch, array(
        CURLOPT_HTTPHEADER => array(
            'Cache-Control: no-cache, no-store, must-revalidate',
            'Pragma: no-cache',
            'Expires: 0'
        )
    ));
}

/**
 * Recursive listing files
 *
 * @param string $directory
 * @param array $entries
 * @param array $visited
 * @return array of files
 */
function recursiveScan($directory, &$entries, &$visited)
{
    // Resolve the real path to handle symlink loops
    $realPath = realpath($directory);
    if (!$realPath || isset($visited[$realPath])) {
        return $entries; // Prevent infinite loops
    }

    // Mark this directory as visited
    $visited[$realPath] = true;

    // Check if the directory exists and is readable
    if (!is_dir($realPath) || !is_readable($realPath)) {
        return $entries;
    }

    // Open the directory
    $handle = opendir($realPath);
    if (!$handle) {
        return $entries;
    }

    // Iterate over the directory contents
    while (($entry = readdir($handle)) !== false) {
        // Skip the current directory and parent directory
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        // Get Nix-style full path
        $entryPath = str_replace(DIRECTORY_SEPARATOR, '/', $realPath . '/' . $entry);
        if (is_link($entryPath)) {
            $entries['symlink'][] = $entryPath;

            // Get the actual symlink target
            $symlinkTarget = readlink($entryPath);
            $resolvedTarget = realpath($symlinkTarget);

            // Follow the symlink only if it's a directory and hasn't been visited
            if ($resolvedTarget && is_dir($resolvedTarget) && !isset($visited[$resolvedTarget])) {
                recursiveScan($resolvedTarget, $entries, $visited);
            }
            continue;
        }

        // Store whether it's a directory to avoid redundant calls
        $isDir = is_dir($entryPath);
        if ($isDir) {
            recursiveScan($entryPath, $entries, $visited);
        } elseif (is_readable($entryPath)) {
            $entries['file_readable'][] = $entryPath;
        } else {
            $entries['file_not_readable'][] = $entryPath;
        }
    }
    closedir($handle);
    return $entries;
}

/**
 *
 * Sort array of list file by lastest modified time
 *
 * @param array  $files Array of files
 * @return array
 *
 */
function sortByLastModified($files)
{
    @array_multisort(array_map('filemtime', $files), SORT_DESC, $files);
    return $files;
}

/**
 *
 * Recurisively list a file by descending modified time
 *
 * @param string $path
 * @return array
 *
 */
function getSortedByTime($path)
{
    $entries = array();
    $visited = array();
    $result = recursiveScan($path, $entries, $visited);
    $readable = $result['file_readable'];
    //$notReadable = isset($result['file_not_readable']) ? $result['file_not_readable'] : array();
    if (isset($result['file_not_readable'])) {
        $notReadable = $result['file_not_readable'];
    } else {
        $notReadable = array();
    }

    $readable = sortByLastModified($readable);
    return array(
        'file_readable' => $readable,
        'file_not_readable' => $notReadable,
    );
}

/**
 * Recursively list a file by descending modified time and pattern matching.
 *
 * @param string $path The directory path to scan.
 * @param array $patterns An array of glob-like patterns to filter (e.g., '*.php[0-9][0-9]').
 * @return array An associative array containing two keys: 'file_readable' and 'file_not_readable'.
 */
function getSortedByPattern($path, $patterns)
{
    $result = getSortedByTime($path);
    $fileReadable = $result['file_readable'];
    $fileNotReadable = $result['file_not_readable'];

    $sortedReadableFiles = array();
    $sortedNotReadableFiles = array();

    foreach ($fileReadable as $entry) {
        $extension = pathinfo($entry, PATHINFO_EXTENSION);

        foreach ($patterns as $pattern) {
            $regex = "/^$pattern$/i";
            if (preg_match($regex, $extension)) {
                $sortedReadableFiles[] = $entry;
                break;
            }
        }
    }

    if ($fileNotReadable) {
        foreach ($fileNotReadable as $entry) {
            $extension = pathinfo($entry, PATHINFO_EXTENSION);

            foreach ($patterns as $pattern) {
                $regex = "/^$pattern$/i";
                if (preg_match($regex, $extension)) {
                    $sortedNotReadableFiles[] = $entry;
                    break;
                }
            }
        }
    }

    return array(
        'file_readable' => $sortedReadableFiles,
        'file_not_readable' => $sortedNotReadableFiles,
    );
}

/**
 * Get lowercase Array of tokens in a file
 *
 * @param string $filename
 * @return array
 */
function getFileTokens($filename)
{
    // Replace short PHP tags with PHP tags
    $fileContent = file_get_contents($filename);
    $fileContent = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $fileContent);
    $fileContent = preg_replace('/<\?([^p=\w])/m', '<?php ', $fileContent);

    $tokens = @token_get_all($fileContent); // https://www.php.net/manual/en/function.token-get-all.php

    $output = array();

    foreach ($tokens as $token) {
        if (is_array($token)) {
            $output[] = $token[1];
        } else {
            $output[] = $token;
        }
    }

    // Remove any duplicate or empty tokens from the output array
    $output = array_values(array_unique(array_filter(array_map("trim", $output))));
    return $output;
}

/**
 * recursively search for a specific case within an array, including nested arrays.
 *
 * @param string $needle
 * @param array $haystack
 * @return array matching case within an array
 */
function inStringArray($needle, $haystack)
{
    $matches = array();
    foreach ($haystack as $key => $value) {
        if (is_string($value)) {
            // Check if string is found using strcasecmp
            if (strcasecmp($value, $needle) === 0) {
                $matches[] = $key;
            }
        } elseif (is_array($value)) {
            // Recursively search within sub-arrays
            $subMatches = inStringArray($needle, $value);
            if (!empty($subMatches)) {
                // Prepend current key to sub-matches
                foreach ($subMatches as $subMatch) {
                    $matches[] = $key . '[' . $subMatch . ']';
                }
            }
        }
    }
    return $matches;
}

/**
 * Compare tokens and return array of matched tokens
 *
 * @param array $tokenNeedles
 * @param array $tokenHaystack
 * @return array
 */
function compareTokens($tokenNeedles, $tokenHaystack)
{
    $output = array();
    foreach ($tokenNeedles as $tokenNeedle) {
        if (inStringArray($tokenNeedle, $tokenHaystack)) {
            $output[] = $tokenNeedle;
        }
    }
    return $output;
}

/**
 * Try every remote download method and return array of strings from a URL.
 *
 * @param string $url
 * @return array
 */
function urlFileArray($url)
{
    $content = false;

    // 1. Try cURL if a global handle exists
    if (isset($GLOBALS['ch'])) {
        curl_setopt($GLOBALS['ch'], CURLOPT_URL, $url);
        curl_setopt($GLOBALS['ch'], CURLOPT_RETURNTRANSFER, true);

        $content = curl_exec($GLOBALS['ch']);

        if ($content === false) {
            $error_msg = curl_error($GLOBALS['ch']);
            trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
        } else {
            return explode("\n", $content);
        }
    }

    // 2. Try file_get_contents
    if (isWorking('file_get_contents')) {
        $context = stream_context_create(array(
            'http' => array(
                'ignore_errors' => true, // Handle potential errors gracefully
                'header' => implode("\r\n", array(
                    'Cache-Control: no-cache, no-store, must-revalidate',
                    'Pragma: no-cache',
                    'Expires: 0'
                )),
            ),
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
            ),
        ));

        $content = @file_get_contents($url, false, $context);

        if ($content !== false) {
            return explode("\n", $content);
        } else {
            trigger_error("Failed to fetch URL using file_get_contents", E_USER_WARNING);
        }
    }

    // 3. Try file()
    if (isWorking('file')) {
        $content = @file($url, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($content !== false) {
            return $content;
        } else {
            trigger_error("Failed to fetch URL using file()", E_USER_WARNING);
        }
    }

    // 4. No suitable method found
    trigger_error("No suitable methods found to fetch URL content", E_USER_WARNING);
    return array();
}

/**
 * Calculate the Shannon entropy of a string.
 *
 * @param string $data The input string.
 * @return float The calculated Shannon entropy.
 */
function shannonEntropy($data)
{
    $len = strlen($data);

    if ($len === 0) {
        return 0;
    }

    $freq = array_count_values(str_split($data));
    $entropy = 0;

    foreach ($freq as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p, 2);
    }
    return $entropy;
}

// $ext = array(
//     'php',
//     'phps',
//     'pht',
//     'phpt',
//     'phtm',
//     'phtml',
//     'phar',
//     'php3',
//     'php4',
//     'php5',
//     'php7',
//     'shtml',
//     'inc',
// );

$pattern = array(
    'ph.+',
    'sh.+',
    'inc',
    'htaccess'
);

$tokenNeedles = array(
    // Obfuscation
    'base64_decode',
    'rawurldecode',
    'urldecode',
    'gzinflate',
    'gzuncompress',
    'str_rot13',
    'convert_uu',
    'htmlspecialchars_decode',
    'bin2hex',
    'hex2bin',
    'hexdec',
    'chr',
    'strrev',
    'goto',
    'implode',
    'strtr',
    'extract',
    'parse_str', //works like extract if only one argument is given.
    'substr',
    'mb_substr',
    'str_replace',
    'substr_replace',
    'preg_replace', // able to do eval on match
    'exif_read_data',
    'readgzfile',

    // Shell / Process
    'eval',
    'exec',
    'shell_exec',
    'system',
    'passthru',
    'pcntl_fork',
    'fsockopen',
    'proc_open',
    'popen ',
    'assert', // identical to eval
    'posix_kill',
    'posix_setpgid',
    'posix_setsid',
    'posix_setuid',
    'proc_nice',
    'proc_close',
    'proc_terminate',
    'apache_child_terminate',

    // Server Information
    'posix_getuid',
    'posix_geteuid',
    'posix_getegid',
    'posix_getpwuid',
    'posix_getgrgid',
    'posix_mkfifo',
    'posix_getlogin',
    'posix_ttyname',
    'getenv',
    'proc_get_status',
    'get_cfg_var',
    'disk_free_space',
    'disk_total_space',
    'diskfreespace',
    'getlastmo',
    'getmyinode',
    'getmypid',
    'getmyuid',
    'getmygid',
    'fileowner',
    'filegroup',
    'get_current_user',
    'pathinfo',
    'getcwd',
    'sys_get_temp_dir',
    'basename',
    'phpinfo',
    'php_uname',

    // Database
    'mysql_connect',
    'mysqli_connect',
    'mysqli_query',
    'mysql_query',

    // I/O
    'fopen',
    'fsockopen',
    'file_put_contents',
    'file_get_contents',
    'url_get_contents',
    'stream_get_meta_data',
    'move_uploaded_file',
    '$_files',
    'copy',
    'include',
    'include_once',
    'require',
    'require_once',
    '__file__',

    // Miscellaneous
    'mail',
    'putenv',
    'curl_init',
    'tmpfile',
    'allow_url_fopen',
    'ini_set',
    'set_time_limit',
    'session_start',
    'symlink',
    '__halt_compiler',
    '__compiler_halt_offset__',
    'error_reporting',
    'create_function',
    'get_magic_quotes_gpc',
    '$auth_pass',
    '$password',
    '$pass',
    '$SISTEMIT_COM_ENC',
);

$whitelistMD5Sums = array();
$blacklistMD5Sums = array();
if (_WHITELIST_) {
    $whitelistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt');
}
if (_BLACKLIST_) {
    $blacklistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt');
}
?>
<!DOCTYPE html>
<html lang="en-us">

    <head>
        <title>Sussy Finder</title>
        <style>
            body {
                font-family: 'Ubuntu Mono', monospace;
                background-color: #1e1e1e;
                color: #d0d0d0;
                font-size: 14px;
            }

            table {
                border-spacing: 0;
                padding: 5px;
                border-radius: 5px;
                border: 1px solid #444;
                width: 90%;
                margin: auto;
                background-color: #2a2a2a;
            }

            tr,
            td {
                padding: 5px;
            }

            th {
                color: #f0f0f0;
                padding: 5px;
                font-size: 20px;
            }

            input,
            button {
                font-family: 'Ubuntu Mono', monospace;
                padding: 5px;
                border-radius: 5px;
                border: 1px solid #555;
                background: #2a2a2a;
                color: #d0d0d0;
            }

            button:hover,
            input[type=submit]:hover,
            input[type=text]:hover {
                border-color: #ff6666;
                color: #ff6666;
                cursor: pointer;
            }

            input[type=text] {
                width: 100%;
            }

            #result td {
                font-size: 12px;
                padding: 3px 6px;
                line-height: 1.4em;
                border-bottom: 1px solid #333;
                white-space: normal;
                word-wrap: break-word;
                overflow-wrap: anywhere;
                max-width: 95vw;
            }

            #result tr:nth-child(even) td {
                background: #242424;
            }

            .control-bar {
                text-align: center;
                margin: 10px 0;
            }

            .control-bar button,
            .control-bar input {
                margin: 0 5px;
            }

            .error-banner {
                background: #3a1a1a;
                color: #ff6b6b;
                padding: 10px;
                border: 1px solid #ff4444;
                border-radius: 5px;
                margin: 10px auto;
                width: 90%;
                text-align: center;
            }

            .file-link {
                cursor: pointer;
                text-decoration: underline;
                text-decoration-style: dotted;
            }

            .file-link:hover {
                color: #ffcc66;
            }

            .verbosity {
                font-size: 11px;
                color: #888;
            }

            .token-highlight {
                color: #ff8a03ff;
            }

            .dashboard-controls {
                text-align: center;
                margin: 10px auto 15px;
            }

            .dashboard-controls button {
                margin: 0 5px;
            }

            .dashboard-panel {
                display: none;
                width: 95%;
                margin: 0 auto 20px;
            }

            .dashboard-panel.visible {
                display: block;
            }

            .dashboard-panel h3 {
                text-align: center;
                color: #ccc;
                margin: 8px 0 15px;
            }

            .insights-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin-bottom: 15px;
            }

            .insight-card {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 12px;
                border-left: 4px solid #4a8bc2;
                text-align: center;
                cursor: pointer;
                transition: border-color 0.2s, background 0.2s;
            }

            .insight-card:hover {
                background: #333;
                border-color: #ffcc66;
            }

            .insight-card.danger { border-left-color: #ff4444; }
            .insight-card.warning { border-left-color: #ffaa00; }
            .insight-card.success { border-left-color: #4CAF50; }
            .insight-card.info { border-left-color: #4a8bc2; }
            .insight-card.purple { border-left-color: #9b59b6; }

            .insight-card .label {
                font-size: 11px;
                color: #888;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .insight-card .value {
                font-size: 22px;
                font-weight: bold;
                color: #f0f0f0;
                margin-top: 5px;
            }

            .insight-card .sub {
                font-size: 11px;
                color: #aaa;
                margin-top: 2px;
            }

            .insight-columns {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }

            .insight-list {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 12px;
            }

            .insight-list h4 {
                color: #ccc;
                margin: 0 0 10px;
            }

            .insight-list table {
                width: 100%;
                border-collapse: collapse;
                font-size: 12px;
            }

            .insight-list th {
                text-align: left;
                color: #888;
                font-weight: normal;
                padding: 4px 6px;
                border-bottom: 1px solid #444;
            }

            .insight-list td {
                padding: 4px 6px;
                border-bottom: 1px solid #333;
            }
            .insight-list .clickable-row {
                cursor: pointer;
            }
            .insight-list .clickable-row:hover td {
                background: #333;
                color: #ffcc66;
            }

            .charts-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }

            .chart-box {
                background: #2a2a2a;
                border-radius: 8px;
                padding: 10px;
                position: relative;
            }

            .chart-box canvas {
                display: block;
                width: 100%;
                height: 300px;
                cursor: crosshair;
            }

            .dashboard-empty {
                color: #888;
                text-align: center;
                padding: 20px;
            }

            /* Tooltip for charts - fixed positioning */
            #chart-tooltip {
                display: none;
                position: fixed;
                background: #1e1e1e;
                border: 1px solid #555;
                border-radius: 6px;
                padding: 8px 12px;
                color: #eee;
                font-size: 12px;
                line-height: 1.5;
                pointer-events: none;
                z-index: 9999;
                max-width: 350px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.7);
                font-family: 'Ubuntu Mono', monospace;
            }
            #chart-tooltip .label {
                color: #aaa;
            }
            #chart-tooltip .value {
                color: #ffcc66;
            }
            #chart-tooltip .mono {
                font-family: 'Ubuntu Mono', monospace;
                word-break: break-all;
            }

            /* Copy MD5 button */
            .copy-hash-btn {
                cursor: pointer;
                color: #4a8bc2;
                margin-left: 6px;
                font-size: 13px;
                background: none;
                border: none;
                padding: 0 4px;
                display: inline-block;
            }
            .copy-hash-btn:hover {
                color: #ffcc66;
            }

            @media (max-width: 768px) {
                .insight-columns,
                .charts-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>

    <body>
        <form method="post">
            <table align="center" width="30%">
                <tr>
                    <th>Sussy Finder</th>
                </tr>
                <tr>
                    <td><input type="text" name="dir" value="<?= getcwd() ?>"></td>
                </tr>
                <tr>
                    <td><input type="submit" name="submit" value="SEARCH"></td>
                </tr>
            </table>
        </form>

        <?php
        if (isset($_POST['submit'])) {
            $path = $_POST['dir'];
            $result = getSortedByPattern($path, $pattern);
            $fileReadable = $result['file_readable'];
            $fileNotReadable = $result['file_not_readable'];

            $rawFeatures = array();
            $duplicateFiles = array();
            $errors = array();

            foreach ($fileReadable as $filePath) {
                $fileSum = md5_file($filePath);
                if (in_array($fileSum, $whitelistMD5Sums))
                    continue;

                $content = file_get_contents($filePath);
                $tokens = getFileTokens($filePath);
                $matchedTokens = compareTokens($tokens, $tokenNeedles);
                $totalTokens = count($tokens);
                $size = filesize($filePath);
                $mtime = filemtime($filePath);
                $entropy = shannonEntropy($content);

                $isBlacklisted = in_array($fileSum, $blacklistMD5Sums);
                $isHtaccess = (pathinfo($filePath, PATHINFO_EXTENSION) == 'htaccess');

                $duplicateOf = false;
                if (($dupPath = array_search($fileSum, $duplicateFiles)) !== false) {
                    $duplicateOf = $dupPath;
                } else {
                    $duplicateFiles[$filePath] = $fileSum;
                }

                $error = null;
                if ($isBlacklisted) {
                    if (!unlink($filePath)) {
                        $error = "Failed to unlink";
                        $errors[] = $error;
                    }
                }

                $rawFeatures[] = array(
                    'path' => $filePath,
                    'size' => $size,
                    'mtime' => $mtime,
                    'total_tokens' => $totalTokens,
                    'matched_tokens' => $matchedTokens,
                    'entropy' => $entropy,
                    'md5' => $fileSum,
                    'is_blacklisted' => $isBlacklisted,
                    'is_htaccess' => $isHtaccess,
                    'duplicate_of' => $duplicateOf,
                    'error' => $error,
                    'is_unreadable' => false,
                );
            }

            foreach ($fileNotReadable as $filePath) {
                $mtime = @filemtime($filePath);

                if (!$mtime) {
                    $mtime = 0;
                }

                $rawFeatures[] = array(
                    'path' => $filePath,
                    'size' => null,
                    'mtime' => $mtime,
                    'total_tokens' => null,
                    'matched_tokens' => array('NOT_READABLE'),
                    'entropy' => null,
                    'md5' => 'N/A',
                    'is_blacklisted' => false,
                    'is_htaccess' => false,
                    'duplicate_of' => false,
                    'error' => null,
                    'is_unreadable' => true,
                );
            }
            echo '<script>const rawFileData = ' . json_encode($rawFeatures) . ';</script>';
        }
        ?>

        <!-- Controls -->
        <div class="control-bar">
            <button type="button" onclick="copyResults()">📋 Copy Results</button>
            <button type="button" onclick="sortResults('mtime')">🕒 Sort by Time</button>
            <button type="button" onclick="sortResults('tokens')">🔢 Sort by Tokens</button>
            <button type="button" onclick="sortResults('zSusp')">📊 Sort by Z‑Score</button>
            <button type="button" onclick="sortResults('residual')">📈 Sort by Residual</button>
            <label style="margin-left:20px;">
                <input type="checkbox" id="showAnomaliesOnly" onchange="toggleAnomalies()"> ⚠️ Only Anomalies
            </label>
            <label style="margin-left:10px;">
                Z‑threshold: <input type="number" id="zThreshold" value="3.5" step="0.1" style="width:60px;"
                    onchange="applyThreshold()">
            </label>
            <!-- Combined search -->
            <label style="margin-left:20px;">
                🔍 Search (filename/token):
                <input type="text" id="searchInput" placeholder="e.g. eval or .php" style="width:180px;" oninput="applySearch()">
            </label>
            <label style="margin-left:5px;">
                <input type="checkbox" id="searchTokensOnly" onchange="applySearch()"> Tokens only
            </label>
        </div>

        <!-- Dashboard controls and panels -->
        <div class="dashboard-controls">
            <button type="button" onclick="toggleInsights()">📋 Show Insights</button>
            <button type="button" onclick="toggleCharts()">📊 Show Charts</button>
            <button type="button" onclick="clearFilters()">🧹 Clear Filters</button>
        </div>

        <div id="insightsPanel" class="dashboard-panel">
            <h3>📋 File System Insights</h3>
            <div id="insightsGrid" class="insights-grid"></div>
            <div class="insight-columns">
                <div id="topSuspicious" class="insight-list">
                    <h4>🔍 Top Suspicious Files</h4>
                </div>
                <div id="topRecent" class="insight-list">
                    <h4>🕒 Most Recent Files</h4>
                </div>
            </div>
        </div>

        <div id="chartsPanel" class="dashboard-panel">
            <h3>📊 Anomaly Visualizations</h3>
            <div id="chartsGrid" class="charts-grid"></div>
        </div>

        <!-- Tooltip for charts -->
        <div id="chart-tooltip"></div>

        <table align="center">
            <tbody id="result"></tbody>
        </table>

        <script>
            // All statistical analysis in browser
            let analyzedData = [];
            let currentSort = 'mtime';
            let currentFilterAnomalies = false;
            let currentThreshold = 3.5;
            let insightsVisible = false;
            let chartsVisible = false;
            let currentSearch = '';
            let searchTokensOnly = false;

            // For chart interactivity
            let chartDataPoints = []; // store point info for each chart

            function computeStats(values) {
                const filtered = values.filter(v => v !== null && !isNaN(v));
                const n = filtered.length;
                if (n === 0) return { mean: 0, std: 0 };
                const mean = filtered.reduce((a, b) => a + b, 0) / n;
                const variance = filtered.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
                return { mean, std: Math.sqrt(variance) };
            }

            function zScore(value, mean, std) {
                if (std === 0 || value === null) return 0;
                return (value - mean) / std;
            }
            function formatDate(timestamp) {
                if (!timestamp) return 'N/A';
                const d = new Date(timestamp * 1000);
                const day = String(d.getDate()).padStart(2, '0');
                const month = String(d.getMonth() + 1).padStart(2, '0');
                const year = d.getFullYear();
                const hours = String(d.getHours()).padStart(2, '0');
                const minutes = String(d.getMinutes()).padStart(2, '0');
                const seconds = String(d.getSeconds()).padStart(2, '0');
                return `${day}/${month}/${year}, ${hours}:${minutes}:${seconds}`;
            }

            function analyzeData(rawData, threshold) {
                const valid = rawData.filter(d => !d.is_unreadable);
                const sizes = valid.map(d => d.size);
                const mtimes = valid.map(d => d.mtime);
                const tokens = valid.map(d => d.total_tokens);
                const susp = valid.map(d => d.matched_tokens ? d.matched_tokens.length : 0);
                const entropies = valid.map(d => d.entropy);

                const stats = {
                    size: computeStats(sizes),
                    mtime: computeStats(mtimes),
                    tokens: computeStats(tokens),
                    susp: computeStats(susp),
                    entropy: computeStats(entropies),
                };

                const avgSuspPerToken = stats.susp.mean / Math.max(1, stats.tokens.mean);

                return rawData.map(d => {
                    if (d.is_unreadable) {
                        return {
                            ...d,
                            zScores: { size: 0, mtime: 0, tokens: 0, susp: 0, entropy: 0 },
                            residual: 0,
                            isAnomaly: true,
                            date: formatDate(d.mtime),
                            suspCount: 0
                        };
                    }

                    const suspCount = d.matched_tokens ? d.matched_tokens.length : 0;
                    const zSize = zScore(d.size, stats.size.mean, stats.size.std);
                    const zMtime = zScore(d.mtime, stats.mtime.mean, stats.mtime.std);
                    const zTokens = zScore(d.total_tokens, stats.tokens.mean, stats.tokens.std);
                    const zSusp = zScore(suspCount, stats.susp.mean, stats.susp.std);
                    const zEntropy = zScore(d.entropy, stats.entropy.mean, stats.entropy.std);

                    const expectedSusp = d.total_tokens * avgSuspPerToken;
                    const residual = suspCount - expectedSusp;

                    const isAnomaly = (Math.abs(zSize) > threshold) ||
                        (Math.abs(zSusp) > threshold) ||
                        (Math.abs(zEntropy) > threshold) ||
                        (Math.abs(zMtime) > threshold) ||
                        (residual > 5) ||
                        d.is_blacklisted ||
                        d.is_htaccess ||
                        d.duplicate_of !== false;

                    return {
                        ...d,
                        zScores: { size: zSize, mtime: zMtime, tokens: zTokens, susp: zSusp, entropy: zEntropy },
                        residual: residual,
                        isAnomaly: isAnomaly,
                        date: d.mtime ? new Date(d.mtime * 1000).toLocaleString() : 'N/A',
                        suspCount: suspCount
                    };
                });
            }

            // Escape HTML
            function escapeHtml(value) {
                if (value === undefined || value === null) return '';
                return String(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }

            // Copy text
            function copyText(text) {
                if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
                    return navigator.clipboard.writeText(text);
                }
                return new Promise((resolve, reject) => {
                    const textarea = document.createElement('textarea');
                    textarea.value = text;
                    textarea.style.position = 'fixed';
                    textarea.style.left = '-9999px';
                    textarea.style.top = '-9999px';
                    document.body.appendChild(textarea);
                    textarea.focus();
                    textarea.select();
                    try {
                        const success = document.execCommand('copy');
                        document.body.removeChild(textarea);
                        if (success) resolve();
                        else reject(new Error('Copy failed'));
                    } catch (e) {
                        document.body.removeChild(textarea);
                        reject(e);
                    }
                });
            }

            // Filtering function that combines anomaly, search, and token-only
            function shouldShowFile(d) {
                if (currentFilterAnomalies && !d.isAnomaly) return false;
                if (!currentSearch.trim()) return true;

                const searchLower = currentSearch.toLowerCase();
                const pathMatch = d.path.toLowerCase().includes(searchLower);
                if (searchTokensOnly) {
                    // Only match tokens
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                } else {
                    // Match path OR tokens
                    if (pathMatch) return true;
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                }
            }

            // Render table
            function renderTable(data) {
                let filtered = data.filter(d => shouldShowFile(d));

                if (currentSort === 'mtime') filtered.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
                else if (currentSort === 'tokens') filtered.sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0));
                else if (currentSort === 'zSusp') filtered.sort((a, b) => Math.abs(b.zScores.susp) - Math.abs(a.zScores.susp));
                else if (currentSort === 'residual') filtered.sort((a, b) => (b.residual || 0) - (a.residual || 0));

                let html = '';
                if (filtered.length === 0) {
                    html = '<tr><td style="color:#888;text-align:center;">No files match the current filters.</td></tr>';
                } else {
                    filtered.forEach(d => {
                        let color = '#dddbdb';
                        let status = '';
                        let verbosity = '';

                        if (d.is_unreadable) {
                            color = '#f72f2f';
                            status = 'NOT_READABLE';
                        } else if (d.is_blacklisted) {
                            color = '#f72f2f';
                            status = 'BLACKLIST';
                            if (d.error) status += ' ' + d.error;
                        } else if (d.is_htaccess) {
                            color = '#66ccff';
                            status = '';
                        } else if (d.duplicate_of !== false) {
                            status = '' + d.duplicate_of;
                        } else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            let tokens = d.matched_tokens.map(t => {
                                const essential = ['base64_decode', 'str_rot13', 'bin2hex', 'hex2bin', 'goto', 'eval', 'exec', 'shell_exec', 'system', 'passthru', 'pcntl_fork', 'fsockopen', 'proc_open', 'popen ', 'posix_kill', 'posix_setpgid', 'posix_setsid', 'posix_setuid', 'fopen', 'fsockopen', 'file_put_contents', 'file_get_contents', 'url_get_contents', 'move_uploaded_file', '$_files', '$auth_pass', '$password', '$pass', '$SISTEMIT_COM_ENC'];
                                if (essential.includes(t)) return '<span class="token-highlight">' + escapeHtml(t) + '</span>';
                                return escapeHtml(t);
                            });
                            status = tokens.join(', ');
                        }

                        if (d.is_unreadable) {
                            verbosity = d.date;
                        } else {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            verbosity = `${d.date} | Size: ${sizeKB} KB, Tokens: ${d.total_tokens || 0}, Suspicious: ${d.suspCount}, Z‑Susp: ${d.zScores.susp.toFixed(1)}, Residual: ${d.residual.toFixed(1)}`;
                        }

                        const warningSign = d.isAnomaly ? '⚠️ ' : '';
                        const fileLink = `<span class="file-link" onclick="copyText('${escapeHtml(d.path)}')">${escapeHtml(d.path)}</span>`;
                        // MD5 copy button (only if readable and has a real MD5)
                        let md5Btn = '';
                        if (!d.is_unreadable && d.md5 && d.md5 !== 'N/A') {
                            md5Btn = `<span class="copy-hash-btn" onclick="copyText('${escapeHtml(d.md5)}')" title="Copy MD5 hash">📋</span>`;
                        }
                        let mainLine = warningSign + fileLink + md5Btn;
                        if (status) mainLine += ' (' + status + ')';

                        html += `<tr>
                            <td style="color:${color}; font-size:14px;">
                                ${mainLine}
                                <br><span class="verbosity">${verbosity}</span>
                            </td>
                        </tr>`;
                    });
                }
                document.getElementById('result').innerHTML = html;
            }

            // Copy full results
            function copyResults() {
                let text = analyzedData
                    .filter(d => shouldShowFile(d))
                    .map(d => {
                        let line = d.path;
                        if (d.is_unreadable) line += ' (NOT_READABLE)';
                        else if (d.is_blacklisted) line += ' (BLACKLIST)';
                        else if (d.is_htaccess) line += ' (HTACCESS)';
                        else if (d.duplicate_of !== false) line += ' (' + d.duplicate_of + ')';
                        else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            line += ' (' + d.matched_tokens.join(', ') + ')';
                        }
                        if (!d.is_unreadable && d.size !== null) {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            line += ` | ${d.date} | Size: ${sizeKB} KB, Tokens: ${d.total_tokens}, Suspicious: ${d.suspCount}, Z-Susp: ${d.zScores.susp.toFixed(1)}, Residual: ${d.residual.toFixed(1)}`;
                            if (d.md5 && d.md5 !== 'N/A') line += ` | MD5: ${d.md5}`;
                        } else {
                            line += ` | ${d.date}`;
                        }
                        return line;
                    })
                    .join('\n');
                copyText(text)
                    .then(() => alert('Results copied!'))
                    .catch(() => alert('Failed to copy.'));
            }

            // Sort, anomaly toggle, threshold
            function sortResults(mode) {
                currentSort = mode;
                renderTable(analyzedData);
            }

            function toggleAnomalies() {
                currentFilterAnomalies = document.getElementById('showAnomaliesOnly').checked;
                renderTable(analyzedData);
            }

            function applyThreshold() {
                const input = document.getElementById('zThreshold');
                const val = parseFloat(input.value);
                if (!isNaN(val) && val >= 0) {
                    currentThreshold = val;
                    if (typeof rawFileData !== 'undefined') {
                        analyzedData = analyzeData(rawFileData, currentThreshold);
                        renderTable(analyzedData);
                        if (insightsVisible) renderInsights(analyzedData);
                        if (chartsVisible) renderCharts(analyzedData);
                    }
                }
            }

            // Combined search
            function applySearch() {
                currentSearch = document.getElementById('searchInput').value;
                searchTokensOnly = document.getElementById('searchTokensOnly').checked;
                renderTable(analyzedData);
            }

            // Clear all filters (except threshold)
            function clearFilters() {
                document.getElementById('showAnomaliesOnly').checked = false;
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterAnomalies = false;
                currentSearch = '';
                searchTokensOnly = false;
                renderTable(analyzedData);
            }

            // Insights with clickable cards and rows
            function toggleInsights() {
                insightsVisible = !insightsVisible;
                const panel = document.getElementById('insightsPanel');
                panel.classList.toggle('visible', insightsVisible);
                if (insightsVisible) renderInsights(analyzedData);
            }

            function renderInsights(data) {
                const grid = document.getElementById('insightsGrid');
                const topSuspicious = document.getElementById('topSuspicious');
                const topRecentPanel = document.getElementById('topRecent');

                if (!data || data.length === 0) {
                    grid.innerHTML = '<div class="dashboard-empty">No scan data available. Run SEARCH first.</div>';
                    topSuspicious.innerHTML = '<h4>🔍 Top Suspicious Files</h4><div class="dashboard-empty">No data.</div>';
                    topRecentPanel.innerHTML = '<h4>🕒 Most Recent Files</h4><div class="dashboard-empty">No data.</div>';
                    return;
                }

                const valid = data.filter(d => !d.is_unreadable && d.size !== null);
                const readable = data.filter(d => !d.is_unreadable);
                const unreadable = data.filter(d => d.is_unreadable).length;
                const blacklisted = data.filter(d => d.is_blacklisted).length;
                const duplicates = data.filter(d => d.duplicate_of !== false).length;
                const htaccess = data.filter(d => d.is_htaccess).length;
                const anomalies = data.filter(d => d.isAnomaly).length;

                let avgSize = 0, minSize = 0, maxSize = 0;
                let avgTokens = 0, minTokens = 0, maxTokens = 0;
                let minMtime = 0, maxMtime = 0;

                if (valid.length > 0) {
                    const sizes = valid.map(d => Number(d.size) || 0);
                    const tokens = valid.map(d => Number(d.total_tokens) || 0);
                    const mtimes = valid.map(d => Number(d.mtime) || 0);

                    avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
                    minSize = Math.min.apply(null, sizes);
                    maxSize = Math.max.apply(null, sizes);

                    avgTokens = tokens.reduce((a, b) => a + b, 0) / tokens.length;
                    minTokens = Math.min.apply(null, tokens);
                    maxTokens = Math.max.apply(null, tokens);

                    minMtime = Math.min.apply(null, mtimes);
                    maxMtime = Math.max.apply(null, mtimes);
                }

                // Helper to create clickable cards that set filters
                function makeCard(label, value, sub, cls, filterFn) {
                    return `<div class="insight-card ${cls}" onclick="applyInsightFilter('${label}', ${filterFn})">
                        <div class="label">${label}</div>
                        <div class="value">${value}</div>
                        <div class="sub">${sub}</div>
                    </div>`;
                }

                grid.innerHTML = `
                    ${makeCard('Total Files', data.length, `${readable.length} readable, ${unreadable} unreadable`, 'info', 'all')}
                    ${makeCard('Anomalies', anomalies, `${data.length ? ((anomalies / data.length) * 100).toFixed(1) : 0}% of total`, anomalies > 0 ? 'danger' : 'success', 'anomaly')}
                    ${makeCard('Blacklisted', blacklisted, `${duplicates} duplicates, ${htaccess} .htaccess`, 'warning', 'blacklisted')}
                    ${makeCard('Average Size', `${(avgSize / 1024).toFixed(1)} KB`, `Min ${(minSize / 1024).toFixed(1)} | Max ${(maxSize / 1024).toFixed(1)}`, 'info', 'all')}
                    ${makeCard('Average Tokens', avgTokens.toFixed(0), `Min ${minTokens} | Max ${maxTokens}`, 'purple', 'all')}
                    ${makeCard('Modification Range', formatDate(minMtime), `to ${formatDate(maxMtime)}`, 'info', 'all')}
                `;

                // Top Suspicious (clickable rows)
                const topSusp = valid.slice().sort((a, b) =>
                    Math.abs((b.zScores && b.zScores.susp) || 0) -
                    Math.abs((a.zScores && a.zScores.susp) || 0)
                ).slice(0, 5);

                let suspHtml = '<h4>🔍 Top Suspicious Files</h4>';
                if (topSusp.length === 0) {
                    suspHtml += '<div class="dashboard-empty">No readable files.</div>';
                } else {
                    suspHtml += '<table>';
                    suspHtml += '<tr><th>File</th><th>|Z-Susp|</th><th>Suspicious</th></tr>';
                    topSusp.forEach(d => {
                        const name = String(d.path || '').split('/').pop() || d.path;
                        const z = Math.abs((d.zScores && d.zScores.susp) || 0);
                        suspHtml += `<tr class="clickable-row" onclick="filterByPath('${escapeHtml(d.path)}')">
                            <td>${escapeHtml(name)}</td>
                            <td>${z.toFixed(2)}</td>
                            <td>${d.suspCount || 0}</td>
                        </tr>`;
                    });
                    suspHtml += '</table>';
                }
                topSuspicious.innerHTML = suspHtml;

                // Most Recent (clickable rows)
                const topRecent = valid.slice().sort((a, b) =>
                    (Number(b.mtime) || 0) - (Number(a.mtime) || 0)
                ).slice(0, 5);

                let recentHtml = '<h4>🕒 Most Recent Files</h4>';
                if (topRecent.length === 0) {
                    recentHtml += '<div class="dashboard-empty">No readable files.</div>';
                } else {
                    recentHtml += '<table><tr><th>File</th><th>Modified</th><th>Size</th></tr>';
                    topRecent.forEach(d => {
                        const name = String(d.path || '').split('/').pop() || d.path;
                        recentHtml += `<tr class="clickable-row" onclick="filterByPath('${escapeHtml(d.path)}')">
                            <td>${escapeHtml(name)}</td>
                            <td>${escapeHtml(d.date || 'N/A')}</td>
                            <td>${((Number(d.size) || 0) / 1024).toFixed(1)} KB</td>
                        </tr>`;
                    });
                    recentHtml += '</table>';
                }
                topRecentPanel.innerHTML = recentHtml;
            }

            // Filter functions called from insights
            function applyInsightFilter(label, type) {
                // Reset other filters, then set specific
                document.getElementById('showAnomaliesOnly').checked = false;
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterAnomalies = false;
                currentSearch = '';
                searchTokensOnly = false;

                if (type === 'anomaly') {
                    document.getElementById('showAnomaliesOnly').checked = true;
                    currentFilterAnomalies = true;
                } else if (type === 'blacklisted') {
                    currentSearch = '__BLACKLIST__';
                    searchTokensOnly = false;
                }
                renderTable(analyzedData);
            }

            // Filter by a specific path (click on insight list item)
            function filterByPath(path) {
                document.getElementById('searchInput').value = path;
                currentSearch = path;
                searchTokensOnly = false;
                document.getElementById('searchTokensOnly').checked = false;
                // Also turn off anomaly filter
                document.getElementById('showAnomaliesOnly').checked = false;
                currentFilterAnomalies = false;
                renderTable(analyzedData);
            }

            // Override shouldShowFile to handle blacklist pseudo-filter
            const originalShouldShow = shouldShowFile;
            shouldShowFile = function(d) {
                if (currentSearch === '__BLACKLIST__') {
                    return d.is_blacklisted === true;
                }
                return originalShouldShow(d);
            };

            // Charts with tooltips and click filtering
            function toggleCharts() {
                chartsVisible = !chartsVisible;
                const panel = document.getElementById('chartsPanel');
                panel.classList.toggle('visible', chartsVisible);
                if (chartsVisible) renderCharts(analyzedData);
            }

            // Helper to position fixed tooltip at mouse
            function positionTooltip(e, tooltip) {
                let leftPos = e.clientX + 12;
                let topPos = e.clientY + 12;
                // Get tooltip dimensions
                const rect = tooltip.getBoundingClientRect();
                if (leftPos + rect.width > window.innerWidth) {
                    leftPos = e.clientX - rect.width - 12;
                }
                if (topPos + rect.height > window.innerHeight) {
                    topPos = e.clientY - rect.height - 12;
                }
                // Ensure not negative
                leftPos = Math.max(0, leftPos);
                topPos = Math.max(0, topPos);
                tooltip.style.left = leftPos + 'px';
                tooltip.style.top = topPos + 'px';
            }

            function renderCharts(data) {
                const grid = document.getElementById('chartsGrid');
                grid.innerHTML = '';

                if (!data || data.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough data to render charts.</div>';
                    return;
                }

                const valid = data.filter(d =>
                    !d.is_unreadable &&
                    d.size !== null &&
                    d.total_tokens !== null &&
                    d.mtime !== null
                );

                if (valid.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough readable files to render charts.</div>';
                    return;
                }

                // Tooltip element for charts
                const tooltip = document.getElementById('chart-tooltip');

                function makeBox(title) {
                    const box = document.createElement('div');
                    box.className = 'chart-box';

                    const titleEl = document.createElement('div');
                    titleEl.style.textAlign = 'center';
                    titleEl.style.color = '#ccc';
                    titleEl.style.marginBottom = '8px';
                    titleEl.textContent = title;
                    box.appendChild(titleEl);

                    const canvas = document.createElement('canvas');
                    canvas.width = 900;
                    canvas.height = 300;
                    box.appendChild(canvas);
                    grid.appendChild(box);

                    return canvas.getContext('2d');
                }

                function clear(ctx) {
                    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
                    ctx.fillStyle = '#2a2a2a';
                    ctx.fillRect(0, 0, ctx.canvas.width, ctx.canvas.height);
                }

                function drawAxes(ctx, left, top, right, bottom) {
                    ctx.strokeStyle = '#666';
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(left, top);
                    ctx.lineTo(left, bottom);
                    ctx.lineTo(right, bottom);
                    ctx.stroke();
                }

                function drawLabel(ctx, text, x, y, align) {
                    ctx.fillStyle = '#aaa';
                    ctx.font = '12px Ubuntu Mono, monospace';
                    ctx.textAlign = align || 'left';
                    ctx.fillText(text, x, y);
                }

                // Helper to draw points with interactivity
                function drawScatter(ctx, left, top, right, bottom, points, xKey, yKey, labelX, labelY) {
                    // points: array of data objects with x and y numeric values, and original data item
                    const maxX = Math.max.apply(null, points.map(p => p.x)) || 1;
                    const maxY = Math.max.apply(null, points.map(p => p.y)) || 1;

                    // Store point coordinates for hit detection
                    const hitPoints = [];

                    points.forEach((p, idx) => {
                        const px = left + (p.x / maxX) * (right - left);
                        const py = bottom - (p.y / maxY) * (bottom - top);
                        const isAnomaly = p.item.isAnomaly;
                        ctx.fillStyle = isAnomaly ? '#ff4444' : '#66a3ff';
                        ctx.beginPath();
                        ctx.arc(px, py, 5, 0, Math.PI * 2);
                        ctx.fill();

                        // Store for hit detection
                        hitPoints.push({ x: px, y: py, data: p.item, index: idx });
                    });

                    // Add hover and click listeners on canvas
                    const canvas = ctx.canvas;
                    // Remove old listeners to avoid duplicates
                    canvas._listeners && canvas._listeners.forEach(l => canvas.removeEventListener(l.type, l.handler));
                    canvas._listeners = [];

                    function getMousePos(e) {
                        const rect = canvas.getBoundingClientRect();
                        return {
                            x: (e.clientX - rect.left) * (canvas.width / rect.width),
                            y: (e.clientY - rect.top) * (canvas.height / rect.height)
                        };
                    }

                    function findHit(mx, my, radius = 10) {
                        for (let hp of hitPoints) {
                            const dx = hp.x - mx;
                            const dy = hp.y - my;
                            if (dx * dx + dy * dy < radius * radius) {
                                return hp;
                            }
                        }
                        return null;
                    }

                    // Mouse move: show tooltip
                    const onMouseMove = function(e) {
                        const pos = getMousePos(e);
                        const hit = findHit(pos.x, pos.y);
                        if (hit) {
                            const d = hit.data;
                            const info = `
                                <div><span class="label">File:</span> <span class="value">${escapeHtml(d.path)}</span></div>
                                <div><span class="label">Size:</span> <span class="value">${(d.size/1024).toFixed(1)} KB</span></div>
                                <div><span class="label">Tokens:</span> <span class="value">${d.total_tokens}</span></div>
                                <div><span class="label">Suspicious:</span> <span class="value">${d.suspCount}</span></div>
                                <div><span class="label">Z‑Susp:</span> <span class="value">${d.zScores.susp.toFixed(2)}</span></div>
                                <div><span class="label">MD5:</span> <span class="value mono">${escapeHtml(d.md5)}</span></div>
                                <div><span class="label">Anomaly:</span> <span class="value">${d.isAnomaly ? '⚠️ Yes' : 'No'}</span></div>
                            `;
                            tooltip.innerHTML = info;
                            tooltip.style.display = 'block';
                            positionTooltip(e, tooltip);
                            canvas.style.cursor = 'pointer';
                        } else {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    };

                    const onMouseLeave = function() {
                        tooltip.style.display = 'none';
                        canvas.style.cursor = 'crosshair';
                    };

                    const onClick = function(e) {
                        const pos = getMousePos(e);
                        const hit = findHit(pos.x, pos.y);
                        if (hit) {
                            // Filter table to this file
                            filterByPath(hit.data.path);
                        }
                    };

                    canvas.addEventListener('mousemove', onMouseMove);
                    canvas.addEventListener('mouseleave', onMouseLeave);
                    canvas.addEventListener('click', onClick);
                    canvas._listeners = [
                        { type: 'mousemove', handler: onMouseMove },
                        { type: 'mouseleave', handler: onMouseLeave },
                        { type: 'click', handler: onClick }
                    ];

                    // Labels
                    drawLabel(ctx, labelX, (left + right) / 2, bottom + 35, 'center');
                    drawLabel(ctx, labelY, 8, top + 10, 'left');
                }

                // 1. Tokens vs Suspicious
                {
                    const ctx = makeBox('Tokens vs Suspicious Count');
                    clear(ctx);
                    const left = 55, top = 20, right = 875, bottom = 250;
                    drawAxes(ctx, left, top, right, bottom);

                    const points = valid.map(d => ({
                        x: d.total_tokens,
                        y: d.suspCount,
                        item: d
                    }));
                    drawScatter(ctx, left, top, right, bottom, points, 'total_tokens', 'suspCount', 'Total Tokens', 'Suspicious Count');
                }

                // 2. Z-score bars - clickable
                {
                    const ctx = makeBox('Top Suspicious Z-Scores');
                    clear(ctx);

                    const selected = valid.slice().sort((a, b) =>
                        Math.abs((b.zScores && b.zScores.susp) || 0) -
                        Math.abs((a.zScores && a.zScores.susp) || 0)
                    ).slice(0, 12);

                    const left = 180, top = 20, right = 875, bottom = 270;
                    const rowH = (bottom - top) / Math.max(1, selected.length);
                    const maxZ = Math.max(
                        currentThreshold,
                        ...selected.map(d => Math.abs((d.zScores && d.zScores.susp) || 0))
                    ) || 1;

                    // Store hit areas for bars
                    const barHitAreas = [];

                    selected.forEach((d, i) => {
                        const z = Math.abs((d.zScores && d.zScores.susp) || 0);
                        const y = top + i * rowH + 3;
                        const w = (z / maxZ) * (right - left);

                        ctx.fillStyle = z > currentThreshold ? '#ff4444' : '#4a8bc2';
                        ctx.fillRect(left, y, w, Math.max(8, rowH - 6));

                        const name = String(d.path || '').split('/').pop() || d.path;
                        drawLabel(ctx, name.length > 24 ? name.slice(0, 21) + '...' : name, left - 8, y + rowH / 2 + 4, 'right');
                        drawLabel(ctx, z.toFixed(2), Math.min(right - 4, left + w + 6), y + rowH / 2 + 4, 'left');

                        barHitAreas.push({
                            x: left,
                            y: y,
                            w: w,
                            h: Math.max(8, rowH - 6),
                            data: d
                        });
                    });

                    // Add click on bars to filter
                    const canvas = ctx.canvas;
                    canvas.addEventListener('click', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w &&
                                my >= bar.y && my <= bar.y + bar.h) {
                                filterByPath(bar.data.path);
                                break;
                            }
                        }
                    });
                    // Add hover for tooltip on bars
                    canvas.addEventListener('mousemove', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        let found = false;
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w &&
                                my >= bar.y && my <= bar.y + bar.h) {
                                const d = bar.data;
                                const info = `
                                    <div><span class="label">File:</span> <span class="value">${escapeHtml(d.path)}</span></div>
                                    <div><span class="label">Z‑Susp:</span> <span class="value">${d.zScores.susp.toFixed(2)}</span></div>
                                    <div><span class="label">Suspicious:</span> <span class="value">${d.suspCount}</span></div>
                                    <div><span class="label">MD5:</span> <span class="value mono">${escapeHtml(d.md5)}</span></div>
                                `;
                                tooltip.innerHTML = info;
                                tooltip.style.display = 'block';
                                positionTooltip(e, tooltip);
                                canvas.style.cursor = 'pointer';
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                    canvas.addEventListener('mouseleave', function() {
                        tooltip.style.display = 'none';
                        canvas.style.cursor = 'crosshair';
                    });
                }
            }

            // Initialize on page load
            window.onload = function () {
                if (typeof rawFileData !== 'undefined') {
                    currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                    analyzedData = analyzeData(rawFileData, currentThreshold);
                    renderTable(analyzedData);
                }
            };
        </script>
    </body>

</html>