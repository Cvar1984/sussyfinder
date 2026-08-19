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
                Z‑threshold: <input type="number" id="zThreshold" value="2.5" step="0.1" style="width:60px;"
                    onchange="applyThreshold()">
            </label>
        </div>

        <table align="center">
            <tbody id="result"></tbody>
        </table>

        <script>
            // All statistical analysis in browser
            let analyzedData = [];
            let currentSort = 'mtime';
            let currentFilterAnomalies = false;
            let currentThreshold = 2.5;

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

            // Render table with main line (file + status) and verbosity line (date + stats)
            function renderTable(data, sortBy, filterAnomalies) {
                let filtered = filterAnomalies ? data.filter(d => d.isAnomaly) : data;

                if (sortBy === 'mtime') filtered.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
                else if (sortBy === 'tokens') filtered.sort((a, b) => (b.suspCount || 0) - (a.suspCount || 0));
                else if (sortBy === 'zSusp') filtered.sort((a, b) => Math.abs(b.zScores.susp) - Math.abs(a.zScores.susp));
                else if (sortBy === 'residual') filtered.sort((a, b) => (b.residual || 0) - (a.residual || 0));

                let html = '';
                if (filtered.length === 0) {
                    html = '<tr><td style="color:#888;text-align:center;">No files match the current filter.</td></tr>';
                } else {
                    filtered.forEach(d => {
                        let color = '#dddbdb';
                        let status = ''; // will be appended to main line
                        let verbosity = ''; // second line

                        // Determine status and color
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
                            // Show tokens with highlighting
                            let tokens = d.matched_tokens.map(t => {
                                const essential = ['base64_decode', 'str_rot13', 'bin2hex', 'hex2bin', 'goto', 'eval', 'exec', 'shell_exec', 'system', 'passthru', 'pcntl_fork', 'fsockopen', 'proc_open', 'popen ', 'posix_kill', 'posix_setpgid', 'posix_setsid', 'posix_setuid', 'fopen', 'fsockopen', 'file_put_contents', 'file_get_contents', 'url_get_contents', 'move_uploaded_file', '$_files', '$auth_pass', '$password', '$pass', '$SISTEMIT_COM_ENC'];
                                if (essential.includes(t)) return '<span class="token-highlight">' + t + '</span>';
                                return t;
                            });
                            status = tokens.join(', ');
                        }

                        // Verbosity line: date + numeric stats (only if readable and not special status that already has them)
                        if (d.is_unreadable) {
                            verbosity = d.date; // just date
                        } else if (d.is_blacklisted || d.is_htaccess || d.duplicate_of !== false) {
                            // For these, we still show date + size + tokens etc.
                            const sizeKB = (d.size / 1024).toFixed(1);
                            verbosity = `${d.date} | Size: ${sizeKB} KB, Tokens: ${d.total_tokens}, Suspicious: ${d.suspCount}, Z‑Susp: ${d.zScores.susp.toFixed(1)}, Residual: ${d.residual.toFixed(1)}`;
                        } else {
                            // Normal file with tokens
                            const sizeKB = (d.size / 1024).toFixed(1);
                            verbosity = `${d.date} | Size: ${sizeKB} KB, Tokens: ${d.total_tokens}, Suspicious: ${d.suspCount}, Z‑Susp: ${d.zScores.susp.toFixed(1)}, Residual: ${d.residual.toFixed(1)}`;
                        }

                        // Build main line: clickable filename + status (if any)
                        const warningSign = d.isAnomaly ? '<span class="warning-sign">⚠️</span> ' : '';
                        const fileLink = `<span class="file-link" onclick="copyHash('${d.md5}')">${d.path}</span>`;
                        let mainLine = warningSign + fileLink;
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

            // Copy hash when filename clicked
            function copyHash(hash) {
                if (hash && hash !== 'N/A') {
                    navigator.clipboard.writeText(hash).then(() => {
                        //alert('Hash copied: ' + hash);
                    }).catch(() => {
                        alert('Failed to copy hash.');
                    });
                } else {
                    alert('No hash available for this file.');
                }
            }

            // Copy full results (main line + verbosity)
            function copyResults() {
                let text = analyzedData
                    .filter(d => currentFilterAnomalies ? d.isAnomaly : true)
                    .map(d => {
                        let line = d.path;
                        // status
                        if (d.is_unreadable) line += ' (NOT_READABLE)';
                        else if (d.is_blacklisted) {
                            line += ' (BLACKLIST)';
                        }
                        else if (d.is_htaccess) line += ' (HTACCESS)';
                        else if (d.duplicate_of !== false) line += ' (' + d.duplicate_of + ')';
                        else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            line += ' (' + d.matched_tokens.join(', ') + ')';
                        }
                        // verbosity: date + stats
                        if (!d.is_unreadable && d.size !== null) {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            line += ` | ${d.date} | Size: ${sizeKB} KB, Tokens: ${d.total_tokens}, Suspicious: ${d.suspCount}, Z-Susp: ${d.zScores.susp.toFixed(1)}, Residual: ${d.residual.toFixed(1)}`;
                        } else {
                            line += ` | ${d.date}`;
                        }
                        return line;
                    })
                    .join('\n');
                navigator.clipboard.writeText(text).then(() => alert('Results copied!')).catch(() => alert('Failed to copy.'));
            }

            function sortResults(mode) {
                currentSort = mode;
                renderTable(analyzedData, currentSort, currentFilterAnomalies);
            }

            function toggleAnomalies() {
                currentFilterAnomalies = document.getElementById('showAnomaliesOnly').checked;
                renderTable(analyzedData, currentSort, currentFilterAnomalies);
            }

            function applyThreshold() {
                const input = document.getElementById('zThreshold');
                const val = parseFloat(input.value);
                if (!isNaN(val) && val >= 0) {
                    currentThreshold = val;
                    if (typeof rawFileData !== 'undefined') {
                        analyzedData = analyzeData(rawFileData, currentThreshold);
                        renderTable(analyzedData, currentSort, currentFilterAnomalies);
                    }
                }
            }

            window.onload = function () {
                if (typeof rawFileData !== 'undefined') {
                    currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 2.5;
                    analyzedData = analyzeData(rawFileData, currentThreshold);
                    renderTable(analyzedData, 'mtime', false);
                }
            };
        </script>
    </body>

</html>