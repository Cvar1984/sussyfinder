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
    $needles = array();
    if (is_array($tokenNeedles)) {
        $keys = array_keys($tokenNeedles);
        if (isset($keys[0]) && is_int($keys[0])) {
            $needles = array_values($tokenNeedles);
        } else {
            $needles = $keys;
        }
    }
    foreach ($needles as $tokenNeedle) {
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

    $freq = count_chars($data, 1);
    $entropy = 0;

    foreach ($freq as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p, 2);
    }
    return $entropy;
}


/**
 * Calculate composite threat score using weighted tokens and combination rules.
 * Backward compatible with PHP 4.3.
 *
 * @param array $matchedTokens
 * @param string $filePath
 * @param float $entropy
 * @param int $size
 * @param array $tokenWeights Master token weights array
 * @return float
 */
function calculateThreatScore($matchedTokens, $filePath, $entropy, $size, $tokenWeights = array())
{
    $score = 0.0;
    $hasCritical = false;
    $hasObfuscation = false;
    $hasUploadReq = false;

    $critTokens = array('eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'assert', 'create_function');
    $obfTokens  = array('base64_decode', 'gzinflate', 'str_rot13', 'gzuncompress', 'convert_uu', 'hex2bin', 'bin2hex');
    $reqTokens  = array('move_uploaded_file', '$_files', 'file_put_contents');

    if (is_array($matchedTokens)) {
        foreach ($matchedTokens as $token) {
            $tokenLower = strtolower($token);
            if (isset($tokenWeights[$tokenLower])) {
                $score += (float)$tokenWeights[$tokenLower];
            } else {
                $score += 1.0;
            }

            if (in_array($tokenLower, $critTokens)) {
                $hasCritical = true;
            }
            if (in_array($tokenLower, $obfTokens)) {
                $hasObfuscation = true;
            }
            if (in_array($tokenLower, $reqTokens)) {
                $hasUploadReq = true;
            }
        }
    }

    // Combination Multipliers
    if ($hasCritical && $hasObfuscation) {
        $score *= 2.5; // High confidence RCE + Obfuscation combo
    }
    if ($hasCritical && $hasUploadReq) {
        $score *= 1.8; // RCE + Upload handling combo
    }

    // Path location penalty (e.g. uploads, tmp, cache, images)
    $pathLower = strtolower(str_replace('\\', '/', $filePath));
    if (strpos($pathLower, 'upload') !== false ||
        strpos($pathLower, 'cache') !== false ||
        strpos($pathLower, 'tmp') !== false ||
        strpos($pathLower, 'images') !== false ||
        strpos($pathLower, 'media') !== false) {
        if ($score > 0 || $entropy > 5.5) {
            $score += 5.0; // Extra suspicion for code in upload/cache locations
        }
    }

    // High Entropy Bonus for small PHP files (< 20KB with entropy > 5.8)
    if ($size !== null && $size < 20480 && $entropy > 5.8) {
        $score += 3.0;
    }

    return round($score, 2);
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

/**
 * Master Token Needles and Threat Weights Map
 * Maps token strings directly to their threat score weights.
 */
$tokenNeedles = array(
    // Critical RCE (Weight: 10.0)
    'eval' => 10.0,
    'exec' => 10.0,
    'shell_exec' => 10.0,
    'system' => 10.0,
    'passthru' => 10.0,
    'proc_open' => 10.0,
    'assert' => 10.0,
    'create_function' => 10.0,
    'pcntl_fork' => 10.0,
    'posix_kill' => 10.0,
    'posix_setuid' => 10.0,

    // High Obfuscation & De-encoding (Weight: 5.0)
    'base64_decode' => 5.0,
    'gzinflate' => 5.0,
    'str_rot13' => 5.0,
    'gzuncompress' => 5.0,
    'convert_uu' => 5.0,
    'rawurldecode' => 5.0,
    'urldecode' => 5.0,
    'hex2bin' => 5.0,
    'bin2hex' => 5.0,
    'exif_read_data' => 5.0,
    'readgzfile' => 5.0,
    '$SISTEMIT_COM_ENC' => 5.0,

    // Obfuscation Helpers & I/O Manipulation (Weight: 2.0)
    'htmlspecialchars_decode' => 2.0,
    'hexdec' => 2.0,
    'chr' => 2.0,
    'strrev' => 2.0,
    'goto' => 2.0,
    'extract' => 2.0,
    'parse_str' => 2.0,
    'popen ' => 2.0,
    'fsockopen' => 2.0,
    'posix_setsid' => 2.0,
    'posix_setpgid' => 2.0,
    'proc_nice' => 2.0,
    'proc_close' => 2.0,
    'proc_terminate' => 2.0,
    'apache_child_terminate' => 2.0,
    'move_uploaded_file' => 2.0,
    '$_files' => 2.0,
    '$auth_pass' => 2.0,
    '$password' => 2.0,
    '$pass' => 2.0,
    'preg_replace' => 2.0,

    // Low / Routine Tokens (Weight: 0.1)
    'implode' => 0.1,
    'strtr' => 0.1,
    'substr' => 0.1,
    'mb_substr' => 0.1,
    'str_replace' => 0.1,
    'substr_replace' => 0.1,
    'basename' => 0.1,
    'getcwd' => 0.1,
    'pathinfo' => 0.1,
    'getenv' => 0.1,
    'get_current_user' => 0.1,
    'fileowner' => 0.1,
    'filegroup' => 0.1,
    'disk_free_space' => 0.1,
    'disk_total_space' => 0.1,
    'sys_get_temp_dir' => 0.1,
    'fopen' => 0.1,
    'file_put_contents' => 0.1,
    'file_get_contents' => 0.1,
    'url_get_contents' => 0.1,
    'stream_get_meta_data' => 0.1,
    'copy' => 0.1,
    'include' => 0.1,
    'require' => 0.1,
    'include_once' => 0.1,
    'require_once' => 0.1,
    '__file__' => 0.1,
    'mail' => 0.1,
    'putenv' => 0.1,
    'curl_init' => 0.1,
    'tmpfile' => 0.1,
    'allow_url_fopen' => 0.1,
    'ini_set' => 0.1,
    'set_time_limit' => 0.1,
    'session_start' => 0.1,
    'symlink' => 0.1,
    '__halt_compiler' => 0.1,
    '__compiler_halt_offset__' => 0.1,
    'error_reporting' => 0.1,
    'get_magic_quotes_gpc' => 0.1
);

$whitelistMD5Sums = array();
$blacklistMD5Sums = array();
if (_WHITELIST_) {
    $whitelistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt');
}
if (_BLACKLIST_) {
    $blacklistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt');
}
// ── AJAX request handler ────────────────────────────────────────────────
if (isset($_POST['ajax_action'])) {
    header('Content-Type: application/json');
    $ajaxAction = $_POST['ajax_action'];

    if ($ajaxAction == 'scan') {
        if (isset($_POST['dir'])) {
            $path = $_POST['dir'];
        } else {
            $path = getcwd();
        }

        $result = getSortedByPattern($path, $pattern);

        if (isset($result['file_readable'])) {
            $readable = $result['file_readable'];
        } else {
            $readable = array();
        }

        if (isset($result['file_not_readable'])) {
            $notReadable = $result['file_not_readable'];
        } else {
            $notReadable = array();
        }

        $filtered = array();
        foreach ($readable as $fp) {
            $sum = md5_file($fp);
            if (!in_array($sum, $whitelistMD5Sums)) {
                $filtered[] = $fp;
            }
        }

        echo json_encode(array(
            'readable'     => array_values($filtered),
            'not_readable' => array_values($notReadable),
            'total'        => count($filtered) + count($notReadable),
        ));
        exit;
    }

    if ($ajaxAction == 'process') {
        if (isset($_POST['paths']) && is_array($_POST['paths'])) {
            $paths = $_POST['paths'];
        } else {
            $paths = array();
        }

        if (isset($_POST['is_not_readable']) && $_POST['is_not_readable'] == '1') {
            $isUnreadable = true;
        } else {
            $isUnreadable = false;
        }

        if (isset($_POST['seen_hashes']) && is_array($_POST['seen_hashes'])) {
            $seenHashes = $_POST['seen_hashes'];
        } else {
            $seenHashes = array();
        }

        $features  = array();
        $newHashes = array();

        if ($isUnreadable) {
            foreach ($paths as $filePath) {
                $mtime = @filemtime($filePath);
                if (!$mtime) {
                    $mtime = 0;
                }
                $features[] = array(
                    'path'           => $filePath,
                    'size'           => null,
                    'mtime'          => $mtime,
                    'total_tokens'   => null,
                    'matched_tokens' => array('NOT_READABLE'),
                    'md5'            => 'N/A',
                    'is_blacklisted' => false,
                    'is_htaccess'    => false,
                    'duplicate_of'   => false,
                    'error'          => null,
                    'is_unreadable'  => true,
                );
            }
        } else {
            $localSeen = array();
            foreach ($seenHashes as $entry) {
                $parts = explode(':', $entry, 2);
                if (count($parts) == 2) {
                    $localSeen[$parts[0]] = $parts[1];
                }
            }

            foreach ($paths as $filePath) {
                if (!file_exists($filePath) || !is_readable($filePath)) {
                    continue;
                }

                $fileSum = md5_file($filePath);
                if (in_array($fileSum, $whitelistMD5Sums)) {
                    continue;
                }

                $tokens        = getFileTokens($filePath);
                $matchedTokens = compareTokens($tokenNeedles, $tokens);
                $totalTokens   = count($tokens);
                $size          = filesize($filePath);
                $mtime         = filemtime($filePath);
                $isBlacklisted = in_array($fileSum, $blacklistMD5Sums);
                $isHtaccess    = (pathinfo($filePath, PATHINFO_EXTENSION) == 'htaccess');
                $duplicateOf   = false;

                if (isset($localSeen[$fileSum])) {
                    $duplicateOf = $localSeen[$fileSum];
                } else {
                    $localSeen[$fileSum] = $filePath;
                    $newHashes[] = $fileSum . ':' . $filePath;
                }

                $error = null;
                if ($isBlacklisted) {
                    if (!@unlink($filePath)) {
                        $error = 'Failed to unlink';
                    }
                }

                $features[] = array(
                    'path'           => $filePath,
                    'size'           => $size,
                    'mtime'          => $mtime,
                    'total_tokens'   => $totalTokens,
                    'matched_tokens' => $matchedTokens,
                    'md5'            => $fileSum,
                    'is_blacklisted' => $isBlacklisted,
                    'is_htaccess'    => $isHtaccess,
                    'duplicate_of'   => $duplicateOf,
                    'error'          => $error,
                    'is_unreadable'  => false,
                );
            }
        }

        echo json_encode(array('features' => $features, 'new_hashes' => $newHashes));
        exit;
    }

    echo json_encode(array('error' => 'Unknown action'));
    exit;
}
// ────────────────────────────────────────────────────────────────────────
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
                    <td><input type="text" name="dir" value="<?php echo getcwd(); ?>"></td>
                </tr>
                <tr>
                    <td><input type="submit" name="submit" value="SCAN" title="Classic full-page scan (may timeout on large directories)">&nbsp;
                    <button type="button" onclick="startChunkedScan()" title="AJAX chunked scan — safe for large directories">AJAX SCAN</button></td>
                </tr>
                <tr>
                    <td style="font-size:12px;color:#888;">
                        Chunk size:&nbsp;<input type="number" id="chunkSizeInput" value="50" step="10" style="width:65px;" title="Files processed per AJAX request">
                        &nbsp;<span style="font-size:11px;color:#666;">(files per batch)</span>
                    </td>
                </tr>
            </table>
        </form>

        <!-- AJAX progress panel -->
        <div id="ajaxProgress" style="display:none;width:90%;margin:10px auto;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <span id="ajaxStatus" style="color:#ccc;font-size:13px;">Scanning...</span>
                <button type="button" onclick="cancelChunkedScan()" style="padding:3px 10px;font-size:12px;">Cancel</button>
            </div>
            <div style="background:#333;border-radius:4px;height:12px;overflow:hidden;">
                <div id="ajaxBar" style="height:100%;width:0%;background:linear-gradient(90deg,#4a8bc2,#ffaa00);transition:width 0.2s;"></div>
            </div>
            <div style="margin-top:4px;font-size:11px;color:#888;" id="ajaxSubStatus"></div>
        </div>

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

                // Token extraction only — entropy and threat score computed client-side
                $tokens = getFileTokens($filePath);
                $matchedTokens = compareTokens($tokenNeedles, $tokens);
                $totalTokens = count($tokens);
                $size = filesize($filePath);
                $mtime = filemtime($filePath);

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
                    if (!@unlink($filePath)) {
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
                    'md5' => 'N/A',
                    'is_blacklisted' => false,
                    'is_htaccess' => false,
                    'duplicate_of' => false,
                    'error' => null,
                    'is_unreadable' => true,
                );
            }
            // Emit token weight map so JS can replicate PHP scoring exactly
            echo '<script>const tokenWeights = ' . json_encode($tokenNeedles) . ';</script>';
            echo '<script>const rawFileData = ' . json_encode($rawFeatures) . ';</script>';
        }
        // Always emit tokenWeights so AJAX scan mode can use them
        if (!isset($_POST['submit'])) {
            echo '<script>const tokenWeights = ' . json_encode($tokenNeedles) . ';</script>';
        }
        ?>
        <!-- Warning banner for critical errors & failed deletions -->
        <div id="warningBanner" class="error-banner" style="display:none;"></div>

        <!-- Controls -->
        <div class="control-bar">
            <button type="button" onclick="copyResults()">Copy Results</button>
            <button type="button" onclick="sortResults('threat')">Sort by Threat Score</button>
            <button type="button" onclick="sortResults('mtime')">Sort by Time</button>
            <button type="button" onclick="sortResults('tokens')">Sort by Tokens</button>
            <button type="button" onclick="sortResults('zSusp')">Sort by Z‑Score</button>
            <button type="button" onclick="sortResults('residual')">Sort by Residual</button>
            <label style="margin-left:15px;">
                Filter:
                <select id="severityFilter" onchange="applySeverityFilter()" style="padding:4px; border-radius:5px; background:#2a2a2a; color:#d0d0d0; border:1px solid #555;">
                    <option value="all">All Files</option>
                    <option value="anomalies">Only Anomalies</option>
                    <option value="critical">Critical Threat</option>
                    <option value="obfuscated">High Entropy</option>
                </select>
            </label>
            <label style="margin-left:10px;">
                Z‑threshold: <input type="number" id="zThreshold" value="3.5" step="0.1" style="width:55px;" onchange="applyThreshold()">
            </label>
            <label style="margin-left:15px;">
                🔍 Search:
                <input type="text" id="searchInput" placeholder="e.g. eval or .php" style="width:160px;" oninput="applySearch()">
            </label>
            <label style="margin-left:5px;">
                <input type="checkbox" id="searchTokensOnly" onchange="applySearch()"> Tokens only
            </label>
        </div>

        <!-- Dashboard controls and panels -->
        <div class="dashboard-controls">
            <button type="button" onclick="toggleInsights()">Show Insights</button>
            <button type="button" onclick="toggleCharts()">Show Charts</button>
            <button type="button" onclick="clearFilters()">Clear Filters</button>
        </div>

        <div id="insightsPanel" class="dashboard-panel">
            <h3>File System & Threat Insights</h3>
            <div id="insightsGrid" class="insights-grid"></div>
            <div class="insight-columns">
                <div id="topSuspicious" class="insight-list">
                    <h4>Top Suspicious Files</h4>
                </div>
                <div id="topRecent" class="insight-list">
                    <h4>Most Recent Files</h4>
                </div>
            </div>
        </div>

        <div id="chartsPanel" class="dashboard-panel">
            <h3>Threat Matrix & Anomaly Visualizations</h3>
            <div id="chartsGrid" class="charts-grid"></div>
        </div>

        <!-- Tooltip for charts -->
        <div id="chart-tooltip"></div>

        <table align="center">
            <tbody id="result"></tbody>
        </table>

        <script>
            // Client-side statistical analysis and graph rendering
            let analyzedData = [];
            let currentSort = 'threat';
            let currentFilterMode = 'all';
            let currentThreshold = 3.5;
            let insightsVisible = false;
            let chartsVisible = false;
            let currentSearch = '';
            let searchTokensOnly = false;

            // --- Client-side threat scoring (offloaded from PHP) ---

            /**
             * Compute Shannon entropy from an array of token strings.
             * Treats each character in each token as a symbol.
             */
            function shannonEntropy(tokens) {
                if (!tokens || tokens.length === 0) return 0;
                var combined = tokens.join('');
                var len = combined.length;
                if (len === 0) return 0;
                var freq = {};
                for (var i = 0; i < len; i++) {
                    var ch = combined[i];
                    freq[ch] = (freq[ch] || 0) + 1;
                }
                var entropy = 0;
                for (var ch in freq) {
                    var p = freq[ch] / len;
                    entropy -= p * Math.log2(p);
                }
                return entropy;
            }

            /**
             * Compute composite threat score — exact JS port of PHP calculateThreatScore().
             * @param {string[]} matchedTokens
             * @param {string}   filePath
             * @param {number}   entropy
             * @param {number}   size       file size in bytes, or null
             * @param {Object}   weights    tokenWeights map (key -> weight)
             */
            function calculateThreatScore(matchedTokens, filePath, entropy, size, weights) {
                var score = 0.0;
                var hasCritical = false;
                var hasObfuscation = false;
                var hasUploadReq = false;

                var critTokens = ['eval','exec','shell_exec','system','passthru','proc_open','assert','create_function'];
                var obfTokens  = ['base64_decode','gzinflate','str_rot13','gzuncompress','convert_uu','hex2bin','bin2hex'];
                var reqTokens  = ['move_uploaded_file','$_files','file_put_contents'];

                if (Array.isArray(matchedTokens)) {
                    for (var i = 0; i < matchedTokens.length; i++) {
                        var token = matchedTokens[i].toLowerCase();
                        if (weights && typeof weights[token] !== 'undefined') {
                            score += parseFloat(weights[token]);
                        } else {
                            score += 1.0;
                        }
                        if (critTokens.indexOf(token) !== -1) hasCritical = true;
                        if (obfTokens.indexOf(token)  !== -1) hasObfuscation = true;
                        if (reqTokens.indexOf(token)  !== -1) hasUploadReq = true;
                    }
                }

                if (hasCritical && hasObfuscation) score *= 2.5;
                if (hasCritical && hasUploadReq)   score *= 1.8;

                var pathLow = (filePath || '').toLowerCase().replace(/\\/g, '/');
                if (pathLow.indexOf('upload')  !== -1 ||
                    pathLow.indexOf('cache')   !== -1 ||
                    pathLow.indexOf('tmp')     !== -1 ||
                    pathLow.indexOf('images')  !== -1 ||
                    pathLow.indexOf('media')   !== -1) {
                    if (score > 0 || entropy > 5.5) score += 5.0;
                }

                if (size !== null && size < 20480 && entropy > 5.8) score += 3.0;

                return Math.round(score * 100) / 100;
            }

            // --- End client-side threat scoring ---

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
                // Compute entropy and threat score client-side (not in PHP payload)
                const entropies = valid.map(d => {
                    return shannonEntropy(d.matched_tokens);
                });

                const weights = (typeof tokenWeights !== 'undefined') ? tokenWeights : {};

                const stats = {
                    size: computeStats(sizes),
                    mtime: computeStats(mtimes),
                    tokens: computeStats(tokens),
                    susp: computeStats(susp),
                    entropy: computeStats(entropies),
                };

                const avgSuspPerToken = stats.susp.mean / Math.max(1, stats.tokens.mean);

                return rawData.map((d, idx) => {
                    if (d.is_unreadable) {
                        return {
                            ...d,
                            entropy: 0,
                            zScores: { size: 0, mtime: 0, tokens: 0, susp: 0, entropy: 0 },
                            residual: 0,
                            isAnomaly: true,
                            threatScore: 0,
                            date: formatDate(d.mtime),
                            suspCount: 0
                        };
                    }

                    const entropy = shannonEntropy(d.matched_tokens);
                    const threatScore = calculateThreatScore(
                        d.matched_tokens, d.path, entropy, d.size, weights
                    );

                    const suspCount = d.matched_tokens ? d.matched_tokens.length : 0;
                    const zSize = zScore(d.size, stats.size.mean, stats.size.std);
                    const zMtime = zScore(d.mtime, stats.mtime.mean, stats.mtime.std);
                    const zTokens = zScore(d.total_tokens, stats.tokens.mean, stats.tokens.std);
                    const zSusp = zScore(suspCount, stats.susp.mean, stats.susp.std);
                    const zEntropy = zScore(entropy, stats.entropy.mean, stats.entropy.std);

                    const expectedSusp = d.total_tokens * avgSuspPerToken;
                    const residual = suspCount - expectedSusp;

                    const isAnomaly = (threatScore >= 8.0) ||
                        (Math.abs(zSize) > threshold) ||
                        (Math.abs(zSusp) > threshold) ||
                        (Math.abs(zEntropy) > threshold) ||
                        (Math.abs(zMtime) > threshold) ||
                        (residual > 5) ||
                        d.is_blacklisted ||
                        d.is_htaccess ||
                        d.duplicate_of !== false;

                    return {
                        ...d,
                        entropy: entropy,
                        zScores: { size: zSize, mtime: zMtime, tokens: zTokens, susp: zSusp, entropy: zEntropy },
                        residual: residual,
                        isAnomaly: isAnomaly,
                        threatScore: threatScore,
                        date: d.mtime ? formatDate(d.mtime) : 'N/A',
                        suspCount: suspCount
                    };
                });
            }

            function escapeHtml(value) {
                if (value === undefined || value === null) return '';
                return String(value)
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
            }

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

            function shouldShowFile(d) {
                if (currentFilterMode === 'anomalies' && !d.isAnomaly) return false;
                if (currentFilterMode === 'critical' && d.threatScore < 10.0 && !d.is_blacklisted) return false;
                if (currentFilterMode === 'obfuscated' && (d.entropy < 5.8 || d.is_unreadable)) return false;

                if (!currentSearch.trim()) return true;

                const searchLower = currentSearch.toLowerCase();
                const pathMatch = d.path.toLowerCase().includes(searchLower);
                if (searchTokensOnly) {
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                } else {
                    if (pathMatch) return true;
                    if (d.matched_tokens && d.matched_tokens.length) {
                        return d.matched_tokens.some(t => t.toLowerCase().includes(searchLower));
                    }
                    return false;
                }
            }

            function renderWarnings(data) {
                var banner = document.getElementById('warningBanner');
                if (!banner) return;

                if (!data || data.length === 0) {
                    banner.style.display = 'none';
                    banner.innerHTML = '';
                    return;
                }

                var failedUnlinks = [];
                var unreadable = [];

                for (var i = 0; i < data.length; i++) {
                    var d = data[i];
                    if (d.is_blacklisted && d.error) {
                        failedUnlinks.push(d);
                    }
                    if (d.is_unreadable) {
                        unreadable.push(d);
                    }
                }

                var html = '';

                if (failedUnlinks.length > 0) {
                    html += '<div style="margin-bottom:6px;">' +
                        '<div style="margin-top:8px;text-align:left;max-height:160px;overflow-y:auto;background:#200;padding:8px 12px;border-radius:4px;border:1px solid #900;">';

                    for (var j = 0; j < failedUnlinks.length; j++) {
                        var f = failedUnlinks[j];
                        html += '<div style="margin:3px 0;font-family:monospace;font-size:12px;"><span style="color:#ff6666;">✖</span> <code style="color:#ffaaaa;">' + escapeHtml(f.path) + '</code> <span style="color:#888;">(' + escapeHtml(f.error) + ')</span></div>';
                    }

                    html += '</div></div>';
                }

                if (unreadable.length > 0) {
                    if (html !== '') {
                        html += '<hr style="border:0;border-top:1px solid #633;margin:8px 0;">';
                    }
                    html += '<div style="font-size:12px;color:#ffaa55;">' +
                        '⚠️ <strong>Permission Warning:</strong> ' + unreadable.length + ' file(s) could not be opened or read during scanning.' +
                        '</div>';
                }

                if (html !== '') {
                    banner.innerHTML = html;
                    banner.style.display = 'block';
                } else {
                    banner.style.display = 'none';
                    banner.innerHTML = '';
                }
            }

            function renderTable(data) {
                renderWarnings(data);
                let filtered = data.filter(d => shouldShowFile(d));

                if (currentSort === 'threat') filtered.sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0));
                else if (currentSort === 'mtime') filtered.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
                else if (currentSort === 'tokens') filtered.sort((a, b) => (b.total_tokens || 0) - (a.total_tokens || 0));
                else if (currentSort === 'zSusp') filtered.sort((a, b) => Math.abs(b.zScores.susp) - Math.abs(a.zScores.susp));
                else if (currentSort === 'residual') filtered.sort((a, b) => (b.residual || 0) - (a.residual || 0));

                let html = '';
                if (filtered.length === 0) {
                    html = '<tr><td style="color:#888;text-align:center;padding:15px;">No files match the current search or filters.</td></tr>';
                } else {
                    filtered.forEach(d => {
                        let color = '#dddbdb';
                        let badge = '';
                        let status = '';
                        let verbosity = '';

                        if (d.is_unreadable) {
                            color = '#f72f2f';
                            badge = '<span style="background:#8b0000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">NOT READABLE</span> ';
                        } else if (d.is_blacklisted) {
                            color = '#f72f2f';
                            badge = '<span style="background:#cc0000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">BLACKLIST</span> ';
                            if (d.error) status = d.error;
                        } else if (d.threatScore >= 15.0) {
                            color = '#ff4444';
                            badge = `<span style="background:#990000;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">CRITICAL (${d.threatScore.toFixed(1)})</span> `;
                        } else if (d.threatScore >= 8.0) {
                            color = '#ffaa00';
                            badge = `<span style="background:#b37700;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">HIGH RISK (${d.threatScore.toFixed(1)})</span> `;
                        } else if (d.is_htaccess) {
                            color = '#66ccff';
                            badge = '<span style="background:#005580;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold;font-size:11px;">HTACCESS</span> ';
                        } else if (d.duplicate_of !== false) {
                            badge = '<span style="background:#444;color:#aaa;padding:2px 6px;border-radius:3px;font-size:11px;">DUPLICATE</span> ';
                            status = d.duplicate_of;
                        } else if (d.matched_tokens && d.matched_tokens.length > 0) {
                            let tokens = d.matched_tokens.map(t => {
                                const essential = ['eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'assert', 'create_function', 'base64_decode', 'str_rot13', 'bin2hex', 'hex2bin', 'gzinflate', 'gzuncompress', '$_files', '$auth_pass', '$password', '$pass', '$SISTEMIT_COM_ENC'];
                                if (essential.includes(t.toLowerCase())) return '<span class="token-highlight">' + escapeHtml(t) + '</span>';
                                return escapeHtml(t);
                            });
                            status = tokens.join(', ');
                        }

                        if (d.is_unreadable) {
                            verbosity = d.date;
                        } else {
                            const sizeKB = (d.size / 1024).toFixed(1);
                            const entStr = d.entropy !== null ? d.entropy.toFixed(2) : 'N/A';
                            verbosity = `${d.date} | Size: ${sizeKB} KB | Tokens: ${d.total_tokens || 0} | Suspicious: ${d.suspCount} | Entropy: ${entStr} | Score: ${d.threatScore.toFixed(1)} | Z‑Susp: ${d.zScores.susp.toFixed(1)}`;
                        }

                        const warningSign = d.isAnomaly ? '⚠️ ' : '';
                        const fileLink = `<span class="file-link" onclick="copyText('${escapeHtml(d.path)}')">${escapeHtml(d.path)}</span>`;
                        let md5Btn = '';
                        if (!d.is_unreadable && d.md5 && d.md5 !== 'N/A') {
                            md5Btn = `<span class="copy-hash-btn" onclick="copyText('${escapeHtml(d.md5)}')" title="Copy MD5 hash">📋</span>`;
                        }
                        let mainLine = warningSign + badge + fileLink + md5Btn;
                        if (status) mainLine += ' (' + status + ')';

                        html += `<tr>
                            <td style="color:${color}; font-size:13px;">
                                ${mainLine}
                                <br><span class="verbosity">${verbosity}</span>
                            </td>
                        </tr>`;
                    });
                }
                document.getElementById('result').innerHTML = html;
            }

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
                            line += ` | ${d.date} | Size: ${sizeKB} KB | ThreatScore: ${d.threatScore.toFixed(1)} | Tokens: ${d.total_tokens} | Suspicious: ${d.suspCount} | Z-Susp: ${d.zScores.susp.toFixed(1)}`;
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

            function sortResults(mode) {
                currentSort = mode;
                renderTable(analyzedData);
            }

            function applySeverityFilter() {
                currentFilterMode = document.getElementById('severityFilter').value;
                renderTable(analyzedData);
            }

            function toggleAnomalies() {
                const checked = document.getElementById('showAnomaliesOnly').checked;
                currentFilterMode = checked ? 'anomalies' : 'all';
                document.getElementById('severityFilter').value = currentFilterMode;
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

            function applySearch() {
                currentSearch = document.getElementById('searchInput').value;
                searchTokensOnly = document.getElementById('searchTokensOnly').checked;
                renderTable(analyzedData);
            }

            function clearFilters() {
                document.getElementById('severityFilter').value = 'all';
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterMode = 'all';
                currentSearch = '';
                searchTokensOnly = false;
                renderTable(analyzedData);
            }

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
                    topSuspicious.innerHTML = '<h4>Top Suspicious Files</h4><div class="dashboard-empty">No data.</div>';
                    topRecentPanel.innerHTML = '<h4>Most Recent Files</h4><div class="dashboard-empty">No data.</div>';
                    return;
                }

                const valid = data.filter(d => !d.is_unreadable && d.size !== null);
                const readable = data.filter(d => !d.is_unreadable);
                const unreadable = data.filter(d => d.is_unreadable).length;
                const blacklisted = data.filter(d => d.is_blacklisted).length;
                const duplicates = data.filter(d => d.duplicate_of !== false).length;
                const htaccess = data.filter(d => d.is_htaccess).length;
                const anomalies = data.filter(d => d.isAnomaly).length;
                const criticalCount = data.filter(d => d.threatScore >= 10.0 || d.is_blacklisted).length;

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

                function makeCard(label, value, sub, cls, filterType) {
                    return `<div class="insight-card ${cls}" onclick="applyInsightFilter('${filterType}')">
                        <div class="label">${label}</div>
                        <div class="value">${value}</div>
                        <div class="sub">${sub}</div>
                    </div>`;
                }

                grid.innerHTML = `
                    ${makeCard('Total Files', data.length, `${readable.length} readable, ${unreadable} unreadable`, 'info', 'all')}
                    ${makeCard('Critical Threats', criticalCount, `${anomalies} total anomalies flagged`, criticalCount > 0 ? 'danger' : 'success', 'critical')}
                    ${makeCard('Blacklisted', blacklisted, `${duplicates} duplicates, ${htaccess} .htaccess`, 'warning', 'blacklisted')}
                    ${makeCard('Average Size', `${(avgSize / 1024).toFixed(1)} KB`, `Min ${(minSize / 1024).toFixed(1)} | Max ${(maxSize / 1024).toFixed(1)}`, 'info', 'all')}
                    ${makeCard('Average Tokens', avgTokens.toFixed(0), `Min ${minTokens} | Max ${maxTokens}`, 'purple', 'all')}
                    ${makeCard('Modification Range', formatDate(minMtime), `to ${formatDate(maxMtime)}`, 'info', 'all')}
                `;

                const topSusp = valid.slice().sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0)).slice(0, 5);

                let suspHtml = '<h4>Top Threat Score Files</h4>';
                if (topSusp.length === 0) {
                    suspHtml += '<div class="dashboard-empty">No readable files.</div>';
                } else {
                    suspHtml += '<table>';
                    suspHtml += '<tr><th>File</th><th>Threat Score</th><th>Tokens</th></tr>';
                    topSusp.forEach(d => {
                        const name = String(d.path || '').split('/').pop() || d.path;
                        suspHtml += `<tr class="clickable-row" onclick="filterByPath('${escapeHtml(d.path)}')">
                            <td>${escapeHtml(name)}</td>
                            <td><strong style="color:${d.threatScore >= 10 ? '#ff4444' : '#ffaa00'}">${d.threatScore.toFixed(1)}</strong></td>
                            <td>${d.suspCount || 0} matched</td>
                        </tr>`;
                    });
                    suspHtml += '</table>';
                }
                topSuspicious.innerHTML = suspHtml;

                const topRecent = valid.slice().sort((a, b) => (Number(b.mtime) || 0) - (Number(a.mtime) || 0)).slice(0, 5);

                let recentHtml = '<h4>Most Recent Files</h4>';
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

            function applyInsightFilter(type) {
                document.getElementById('searchInput').value = '';
                document.getElementById('searchTokensOnly').checked = false;
                currentSearch = '';
                searchTokensOnly = false;

                if (type === 'critical') {
                    currentFilterMode = 'critical';
                } else if (type === 'blacklisted') {
                    currentSearch = '__BLACKLIST__';
                    currentFilterMode = 'all';
                } else if (type === 'anomaly') {
                    currentFilterMode = 'anomalies';
                } else {
                    currentFilterMode = 'all';
                }
                document.getElementById('severityFilter').value = currentFilterMode;
                renderTable(analyzedData);
            }

            function filterByPath(path) {
                document.getElementById('searchInput').value = path;
                currentSearch = path;
                searchTokensOnly = false;
                document.getElementById('searchTokensOnly').checked = false;
                currentFilterMode = 'all';
                document.getElementById('severityFilter').value = 'all';
                renderTable(analyzedData);
            }

            const originalShouldShow = shouldShowFile;
            shouldShowFile = function(d) {
                if (currentSearch === '__BLACKLIST__') {
                    return d.is_blacklisted === true;
                }
                return originalShouldShow(d);
            };

            function toggleCharts() {
                chartsVisible = !chartsVisible;
                const panel = document.getElementById('chartsPanel');
                panel.classList.toggle('visible', chartsVisible);
                if (chartsVisible) renderCharts(analyzedData);
            }

            function positionTooltip(e, tooltip) {
                let leftPos = e.clientX + 12;
                let topPos = e.clientY + 12;
                const rect = tooltip.getBoundingClientRect();
                if (leftPos + rect.width > window.innerWidth) {
                    leftPos = e.clientX - rect.width - 12;
                }
                if (topPos + rect.height > window.innerHeight) {
                    topPos = e.clientY - rect.height - 12;
                }
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

                const valid = data.filter(d => !d.is_unreadable && d.size !== null && d.mtime !== null);

                if (valid.length < 2) {
                    grid.innerHTML = '<div class="dashboard-empty">Not enough readable files to render charts.</div>';
                    return;
                }

                const tooltip = document.getElementById('chart-tooltip');

                function makeBox(title) {
                    const box = document.createElement('div');
                    box.className = 'chart-box';

                    const titleEl = document.createElement('div');
                    titleEl.style.textAlign = 'center';
                    titleEl.style.color = '#ccc';
                    titleEl.style.marginBottom = '8px';
                    titleEl.style.fontWeight = 'bold';
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
                    ctx.strokeStyle = '#555';
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(left, top);
                    ctx.lineTo(left, bottom);
                    ctx.lineTo(right, bottom);
                    ctx.stroke();
                }

                function drawLabel(ctx, text, x, y, align, color) {
                    ctx.fillStyle = color || '#aaa';
                    ctx.font = '12px Ubuntu Mono, monospace';
                    ctx.textAlign = align || 'left';
                    ctx.fillText(text, x, y);
                }

                // 1. QUADRANT THREAT MATRIX: Token Suspicion Ratio vs Composite Threat Score
                {
                    const ctx = makeBox('Threat Matrix: Token Suspicion Ratio vs Threat Score');
                    const canvas = ctx.canvas;
                    const left = 70, top = 30, right = 860, bottom = 255;
                    const W = right - left, H = bottom - top;

                    // raw data points
                    const pts = valid.map(d => ({
                        ratio: d.total_tokens > 0 ? (d.suspCount || 0) / d.total_tokens : 0,
                        score: d.threatScore || 0,
                        data: d
                    }));

                    // auto-fit initial axes to actual data range
                    const xThresh = 0.15, yThresh = 8.0;
                    let rawMaxRatio = 0.01, rawMaxScore = 1;
                    pts.forEach(p => {
                        if (p.ratio > rawMaxRatio) rawMaxRatio = p.ratio;
                        if (p.score > rawMaxScore) rawMaxScore = p.score;
                    });
                    let view = {
                        xLo: 0, xHi: rawMaxRatio * 1.15 + 0.001,
                        yLo: 0, yHi: rawMaxScore * 1.12 + 0.5
                    };

                    const hitPoints = [];

                    function drawThreatMatrix() {
                        clear(ctx);
                        const xRange = view.xHi - view.xLo || 1;
                        const yRange = view.yHi - view.yLo || 1;

                        drawAxes(ctx, left, top, right, bottom);

                        // quadrant dividers
                        const qx = left + ((xThresh - view.xLo) / xRange) * W;
                        const qy = bottom - ((yThresh - view.yLo) / yRange) * H;
                        ctx.save(); ctx.strokeStyle = '#555'; ctx.lineWidth = 1; ctx.setLineDash([5,4]);
                        ctx.beginPath();
                        if (qx > left && qx < right) { ctx.moveTo(qx, top); ctx.lineTo(qx, bottom); }
                        if (qy > top && qy < bottom) { ctx.moveTo(left, qy); ctx.lineTo(right, qy); }
                        ctx.stroke(); ctx.setLineDash([]); ctx.restore();

                        // quadrant labels
                        ctx.font = '10px Ubuntu Mono, monospace';
                        ctx.textAlign = 'right';  ctx.fillStyle = '#ff4444'; ctx.fillText('OBFUSCATED WEBSHELL', right-4, top+14);
                        ctx.textAlign = 'left';   ctx.fillStyle = '#ffaa00'; ctx.fillText('RCE SCRIPT', left+4, top+14);
                        ctx.textAlign = 'right';  ctx.fillStyle = '#4a8bc2'; ctx.fillText('DENSE NORMAL', right-4, bottom-6);
                        ctx.textAlign = 'left';   ctx.fillStyle = '#777';    ctx.fillText('BENIGN', left+4, bottom-6);

                        // Y ticks
                        ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                        for (let t = 0; t <= 5; t++) {
                            const v = view.yLo + (yRange * t) / 5;
                            const y = bottom - ((v - view.yLo) / yRange) * H;
                            ctx.fillText(v.toFixed(1), left-4, y+4);
                            ctx.save(); ctx.strokeStyle='#333'; ctx.lineWidth=1;
                            ctx.beginPath(); ctx.moveTo(left-3,y); ctx.lineTo(left,y); ctx.stroke(); ctx.restore();
                        }

                        // X ticks
                        ctx.textAlign = 'center';
                        for (let t = 0; t <= 5; t++) {
                            const v = view.xLo + (xRange * t) / 5;
                            const x = left + ((v - view.xLo) / xRange) * W;
                            ctx.fillText((v * 100).toFixed(1) + '%', x, bottom+14);
                            ctx.save(); ctx.strokeStyle='#333'; ctx.lineWidth=1;
                            ctx.beginPath(); ctx.moveTo(x,bottom); ctx.lineTo(x,bottom+3); ctx.stroke(); ctx.restore();
                        }

                        // axis labels
                        ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                        ctx.fillText('Suspicious Token Ratio — scroll to zoom, drag to pan, dblclick to reset', left+W/2, bottom+28);
                        ctx.save(); ctx.translate(14, top+H/2); ctx.rotate(-Math.PI/2);
                        ctx.fillText('Threat Score', 0, 0); ctx.restore();

                        // dots
                        hitPoints.length = 0;
                        pts.forEach(p => {
                            const px = left + ((p.ratio - view.xLo) / xRange) * W;
                            const py = bottom - ((p.score - view.yLo) / yRange) * H;
                            if (px < left || px > right || py < top || py > bottom) return;
                            let color;
                            if (p.score >= yThresh && p.ratio >= xThresh) color = '#ff4444';
                            else if (p.score >= yThresh)                  color = '#ffaa00';
                            else if (p.ratio >= xThresh)                  color = '#4a8bc2';
                            else                                           color = '#555';
                            ctx.fillStyle = color;
                            ctx.beginPath(); ctx.arc(px, py, 3.5, 0, Math.PI*2); ctx.fill();
                            hitPoints.push({ x: px, y: py, data: p.data, ratio: p.ratio });
                        });
                    }

                    drawThreatMatrix();

                    // wheel zoom around cursor
                    canvas.addEventListener('wheel', function(e) {
                        e.preventDefault();
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        const fx = Math.max(0, Math.min(1, (mx - left) / W));
                        const fy = Math.max(0, Math.min(1, (my - top) / H));
                        const f = e.deltaY > 0 ? 1.08 : 0.925;
                        const xR = view.xHi - view.xLo, yR = view.yHi - view.yLo;
                        const pivX = view.xLo + fx * xR, pivY = view.yHi - fy * yR;
                        view.xLo = Math.max(0, pivX - fx * xR * f);
                        view.xHi = pivX + (1 - fx) * xR * f;
                        view.yLo = Math.max(0, pivY - (1 - fy) * yR * f);
                        view.yHi = pivY + fy * yR * f;
                        drawThreatMatrix();
                    }, { passive: false });

                    // drag pan
                    let tmDrag = false, tmLX = 0, tmLY = 0;
                    canvas.addEventListener('mousedown', function(e) {
                        if (e.button !== 0) return;
                        tmDrag = true; tmLX = e.clientX; tmLY = e.clientY;
                        canvas.style.cursor = 'grabbing'; e.preventDefault();
                    });
                    document.addEventListener('mousemove', function(e) {
                        if (!tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const dx = (e.clientX - tmLX) / rect.width  * (view.xHi - view.xLo) * (canvas.width  / W);
                        const dy = (e.clientY - tmLY) / rect.height * (view.yHi - view.yLo) * (canvas.height / H);
                        view.xLo -= dx; view.xHi -= dx;
                        view.yLo += dy; view.yHi += dy;
                        if (view.xLo < 0) { view.xHi -= view.xLo; view.xLo = 0; }
                        if (view.yLo < 0) { view.yHi -= view.yLo; view.yLo = 0; }
                        tmLX = e.clientX; tmLY = e.clientY;
                        drawThreatMatrix();
                    });
                    document.addEventListener('mouseup', function() {
                        if (tmDrag) { tmDrag = false; canvas.style.cursor = 'crosshair'; }
                    });

                    // hover tooltip
                    canvas.addEventListener('mousemove', function(e) {
                        if (tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
                        let hit = null;
                        for (let j = 0; j < hitPoints.length; j++) {
                            const hp = hitPoints[j];
                            if ((hp.x-mx)**2 + (hp.y-my)**2 < 100) { hit = hp; break; }
                        }
                        if (hit) {
                            const d = hit.data;
                            tooltip.innerHTML =
                                '<div><span class="label">File:</span> <span class="value">' + escapeHtml(d.path) + '</span></div>' +
                                '<div><span class="label">Threat Score:</span> <span class="value">' + d.threatScore.toFixed(1) + '</span></div>' +
                                '<div><span class="label">Token Ratio:</span> <span class="value">' + (hit.ratio*100).toFixed(1) + '%</span></div>' +
                                '<div><span class="label">Matched / Total:</span> <span class="value">' + (d.suspCount||0) + ' / ' + d.total_tokens + '</span></div>' +
                                '<div><span class="label">Matched:</span> <span class="value">' + escapeHtml((d.matched_tokens||[]).join(', ')) + '</span></div>';
                            tooltip.style.display = 'block';
                            positionTooltip(e, tooltip);
                            canvas.style.cursor = 'pointer';
                        } else {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                    canvas.addEventListener('click', function(e) {
                        if (tmDrag) return;
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
                        for (let j = 0; j < hitPoints.length; j++) {
                            const hp = hitPoints[j];
                            if ((hp.x-mx)**2 + (hp.y-my)**2 < 100) { filterByPath(hp.data.path); break; }
                        }
                    });
                    // double-click resets to auto-fit
                    canvas.addEventListener('dblclick', function() {
                        view = { xLo:0, xHi:rawMaxRatio*1.15+0.001, yLo:0, yHi:rawMaxScore*1.12+0.5 };
                        drawThreatMatrix();
                    });
                }

                // 2. TIMELINE HISTOGRAM: File Modifications over Time
                {
                    const ctx = makeBox('Incident Timeline: File Modifications over Time');
                    clear(ctx);
                    const left = 60, top = 25, right = 870, bottom = 250;
                    drawAxes(ctx, left, top, right, bottom);

                    const mtimes = valid.map(d => d.mtime).filter(t => t > 0).sort((a, b) => a - b);
                    if (mtimes.length > 0) {
                        const minT = mtimes[0];
                        const maxT = mtimes[mtimes.length - 1];
                        const span = Math.max(1, maxT - minT);

                        const numBuckets = 20;
                        const bucketSize = span / numBuckets;
                        const buckets = [];
                        for (let i = 0; i < numBuckets; i++) {
                            buckets.push({ count: 0, maxThreat: 0, files: [] });
                        }

                        valid.forEach(d => {
                            if (!d.mtime) return;
                            let idx = Math.floor((d.mtime - minT) / bucketSize);
                            if (idx >= numBuckets) idx = numBuckets - 1;
                            if (idx < 0) idx = 0;
                            buckets[idx].count++;
                            if (d.threatScore > buckets[idx].maxThreat) buckets[idx].maxThreat = d.threatScore;
                            buckets[idx].files.push(d);
                        });

                        const maxBucketCount = Math.max(1, ...buckets.map(b => b.count));
                        const barW = (right - left) / numBuckets - 3;
                        const hitBars = [];

                        buckets.forEach((b, i) => {
                            const bx = left + i * ((right - left) / numBuckets) + 1;
                            const barH = (b.count / maxBucketCount) * (bottom - top);
                            const by = bottom - barH;

                            let color = '#4a8bc2';
                            if (b.maxThreat >= 10.0) color = '#ff4444';
                            else if (b.maxThreat >= 5.0) color = '#ffaa00';

                            ctx.fillStyle = color;
                            ctx.fillRect(bx, by, barW, barH);

                            hitBars.push({ x: bx, y: by, w: barW, h: barH, bucket: b, time: minT + i * bucketSize });
                        });

                        const canvas = ctx.canvas;
                        canvas.addEventListener('mousemove', function(e) {
                            const rect = canvas.getBoundingClientRect();
                            const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                            const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                            let found = false;
                            for (let hb of hitBars) {
                                if (mx >= hb.x && mx <= hb.x + hb.w && my >= hb.y && my <= bottom) {
                                    const info = `
                                        <div><span class="label">Timeframe:</span> <span class="value">${formatDate(hb.time)}</span></div>
                                        <div><span class="label">Files Modified:</span> <span class="value">${hb.bucket.count}</span></div>
                                        <div><span class="label">Max Threat Score:</span> <span class="value">${hb.bucket.maxThreat.toFixed(1)}</span></div>
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

                        drawLabel(ctx, formatDate(minT), left, bottom + 35, 'left');
                        drawLabel(ctx, formatDate(maxT), right, bottom + 35, 'right');
                        drawLabel(ctx, 'File Count', 8, top + 10, 'left');
                    }
                }

                // 3. TOP THREAT SCORES BAR CHART
                {
                    const ctx = makeBox('Top Composite Threat Scores');
                    clear(ctx);

                    const selected = valid.slice().sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0)).slice(0, 12);
                    const left = 200, top = 20, right = 870, bottom = 270;
                    const rowH = (bottom - top) / Math.max(1, selected.length);
                    const maxScore = Math.max(10.0, ...selected.map(d => d.threatScore || 0));

                    const barHitAreas = [];

                    selected.forEach((d, i) => {
                        const score = d.threatScore || 0;
                        const y = top + i * rowH + 3;
                        const w = (score / maxScore) * (right - left);

                        ctx.fillStyle = score >= 10.0 ? '#ff4444' : (score >= 5.0 ? '#ffaa00' : '#4a8bc2');
                        ctx.fillRect(left, y, w, Math.max(8, rowH - 6));

                        const name = String(d.path || '').split('/').pop() || d.path;
                        drawLabel(ctx, name.length > 26 ? name.slice(0, 23) + '...' : name, left - 8, y + rowH / 2 + 4, 'right');
                        drawLabel(ctx, score.toFixed(1), Math.min(right - 4, left + w + 6), y + rowH / 2 + 4, 'left');

                        barHitAreas.push({ x: left, y: y, w: w, h: Math.max(8, rowH - 6), data: d });
                    });

                    const canvas = ctx.canvas;
                    canvas.addEventListener('click', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w && my >= bar.y && my <= bar.y + bar.h) {
                                filterByPath(bar.data.path);
                                break;
                            }
                        }
                    });
                    canvas.addEventListener('mousemove', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        let found = false;
                        for (let bar of barHitAreas) {
                            if (mx >= bar.x && mx <= bar.x + bar.w && my >= bar.y && my <= bar.y + bar.h) {
                                const d = bar.data;
                                const info = `
                                    <div><span class="label">File:</span> <span class="value">${escapeHtml(d.path)}</span></div>
                                    <div><span class="label">Threat Score:</span> <span class="value">${d.threatScore.toFixed(1)}</span></div>
                                    <div><span class="label">Matched Tokens:</span> <span class="value">${escapeHtml((d.matched_tokens || []).join(', '))}</span></div>
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
                }

                // 4. ENTROPY DISTRIBUTION — sorted scatter, Y range follows data density (no blank space)
                {
                    const ctx = makeBox('Entropy Distribution (sorted, data-density range)');
                    clear(ctx);

                    // Sort by entropy ascending
                    const eData = valid.slice().sort((a, b) => (a.entropy || 0) - (b.entropy || 0));
                    const entVals = eData.map(d => d.entropy || 0);
                    const eMin = entVals[0] || 0;
                    const eMax = entVals[entVals.length - 1] || 1;
                    const ePad = Math.max(0.05, (eMax - eMin) * 0.06);
                    const yLo = Math.max(0, eMin - ePad);
                    const yHi = eMax + ePad;
                    const eRange = yHi - yLo || 1;

                    const left = 55, top = 25, right = 870, bottom = 260;
                    const W = right - left, H = bottom - top;

                    // Percentile gridlines (25 / 50 / 75)
                    const p25 = entVals[Math.floor(entVals.length * 0.25)] || 0;
                    const p50 = entVals[Math.floor(entVals.length * 0.50)] || 0;
                    const p75 = entVals[Math.floor(entVals.length * 0.75)] || 0;
                    [[p25,'#3a5a3a','P25'],[p50,'#5a5a2a','P50'],[p75,'#5a3a2a','P75']].forEach(function([pv, col, lbl]) {
                        const py = bottom - ((pv - yLo) / eRange) * H;
                        ctx.save();
                        ctx.strokeStyle = col;
                        ctx.lineWidth = 1;
                        ctx.setLineDash([4, 4]);
                        ctx.beginPath(); ctx.moveTo(left, py); ctx.lineTo(right, py); ctx.stroke();
                        ctx.setLineDash([]);
                        ctx.fillStyle = col;
                        ctx.font = '10px Ubuntu Mono, monospace';
                        ctx.textAlign = 'left';
                        ctx.fillText(lbl + ' ' + pv.toFixed(2), left + 4, py - 3);
                        ctx.restore();
                    });

                    drawAxes(ctx, left, top, right, bottom);

                    // Y-axis ticks (5 steps across actual data range)
                    ctx.fillStyle = '#888'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'right';
                    for (let t = 0; t <= 5; t++) {
                        const v = yLo + (eRange * t) / 5;
                        const y = bottom - ((v - yLo) / eRange) * H;
                        ctx.fillText(v.toFixed(2), left - 4, y + 4);
                        ctx.save(); ctx.strokeStyle = '#333'; ctx.lineWidth = 1;
                        ctx.beginPath(); ctx.moveTo(left - 3, y); ctx.lineTo(left, y); ctx.stroke();
                        ctx.restore();
                    }

                    // X-axis label
                    ctx.fillStyle = '#aaa'; ctx.font = '11px Ubuntu Mono, monospace'; ctx.textAlign = 'center';
                    ctx.fillText('Files sorted by entropy (low → high)', left + W / 2, bottom + 18);
                    ctx.save(); ctx.translate(13, top + H / 2); ctx.rotate(-Math.PI / 2);
                    ctx.fillText('Shannon Entropy', 0, 0); ctx.restore();

                    // Plot dots
                    const eHits = [];
                    eData.forEach(function(d, i) {
                        const px = left + (i / Math.max(1, eData.length - 1)) * W;
                        const py = bottom - ((( d.entropy || 0) - yLo) / eRange) * H;
                        let col;
                        if (d.threatScore >= 15) col = '#ff4444';
                        else if (d.threatScore >= 8)  col = '#ffaa00';
                        else if ((d.entropy || 0) > 5.8) col = '#9b59b6';
                        else col = '#4a8bc2';
                        ctx.fillStyle = col;
                        ctx.beginPath(); ctx.arc(px, py, 3, 0, Math.PI * 2); ctx.fill();
                        eHits.push({ x: px, y: py, data: d });
                    });

                    // Legend
                    const leg = [['#ff4444','Critical (≥15)'],['#ffaa00','High Risk (≥8)'],['#9b59b6','High Entropy (>5.8)'],['#4a8bc2','Normal']];
                    let lx = left + 4;
                    leg.forEach(function([c, lbl]) {
                        ctx.fillStyle = c; ctx.beginPath(); ctx.arc(lx + 5, top + 12, 4, 0, Math.PI * 2); ctx.fill();
                        ctx.fillStyle = '#aaa'; ctx.font = '10px Ubuntu Mono, monospace'; ctx.textAlign = 'left';
                        ctx.fillText(lbl, lx + 13, top + 16);
                        lx += ctx.measureText(lbl).width + 26;
                    });

                    const canvas = ctx.canvas;
                    canvas.addEventListener('mousemove', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        let hit = null;
                        for (let h of eHits) {
                            const dx = h.x - mx, dy = h.y - my;
                            if (dx*dx + dy*dy < 100) { hit = h; break; }
                        }
                        if (hit) {
                            const d = hit.data;
                            tooltip.innerHTML =
                                '<div><span class="label">File:</span> <span class="value">' + escapeHtml(d.path) + '</span></div>' +
                                '<div><span class="label">Entropy:</span> <span class="value">' + (d.entropy||0).toFixed(4) + '</span></div>' +
                                '<div><span class="label">Threat Score:</span> <span class="value">' + d.threatScore.toFixed(1) + '</span></div>' +
                                '<div><span class="label">Matched Tokens:</span> <span class="value">' + escapeHtml((d.matched_tokens||[]).join(', ')) + '</span></div>';
                            tooltip.style.display = 'block';
                            positionTooltip(e, tooltip);
                            canvas.style.cursor = 'pointer';
                        } else {
                            tooltip.style.display = 'none';
                            canvas.style.cursor = 'crosshair';
                        }
                    });
                    canvas.addEventListener('click', function(e) {
                        const rect = canvas.getBoundingClientRect();
                        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
                        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
                        for (let h of eHits) {
                            const dx = h.x - mx, dy = h.y - my;
                            if (dx*dx + dy*dy < 100) { filterByPath(h.data.path); break; }
                        }
                    });
                }
            }

            // ── Chunked AJAX scan ────────────────────────────────────────────
            var _scanCancelled = false;
            var _seenHashes = [];

            function getChunkSize() {
                var el = document.getElementById('chunkSizeInput');
                var val = el ? parseInt(el.value, 10) : 25;
                if (isNaN(val) || val < 1) {
                    val = 25;
                }
                return val;
            }


            function startChunkedScan() {
                var dirInput = document.querySelector('input[name="dir"]');
                var dir = dirInput ? dirInput.value.trim() : '';
                if (!dir) { alert('Enter a directory path first.'); return; }

                var chunkSize = getChunkSize();
                _scanCancelled = false;
                _seenHashes = [];
                var allFeatures = [];

                var warnEl = document.getElementById('warningBanner');
                if (warnEl) { warnEl.style.display = 'none'; warnEl.innerHTML = ''; }

                document.getElementById('ajaxProgress').style.display = 'block';
                document.getElementById('ajaxBar').style.width = '0%';
                document.getElementById('ajaxStatus').textContent = 'Phase 1: Scanning directory\u2026';
                document.getElementById('ajaxSubStatus').textContent = '';
                document.getElementById('result').innerHTML = '';
                analyzedData = [];

                var body = new URLSearchParams();
                body.set('ajax_action', 'scan');
                body.set('dir', dir);

                fetch('', { method: 'POST', body: body })
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (_scanCancelled) { return; }
                        var readable    = data.readable    || [];
                        var notReadable = data.not_readable || [];
                        var total       = data.total || (readable.length + notReadable.length);

                        document.getElementById('ajaxStatus').textContent =
                            'Phase 2: Processing ' + total + ' files\u2026 (chunk size: ' + chunkSize + ')';

                        // Build flat chunk list
                        var chunks = [];
                        for (var i = 0; i < readable.length; i += chunkSize) {
                            chunks.push({ paths: readable.slice(i, i + chunkSize), isNotReadable: false });
                        }
                        for (var j = 0; j < notReadable.length; j += chunkSize) {
                            chunks.push({ paths: notReadable.slice(j, j + chunkSize), isNotReadable: true });
                        }

                        return processChunk(chunks, 0, allFeatures, total, chunkSize);
                    })
                    .then(function() {
                        if (_scanCancelled) { return; }
                        document.getElementById('ajaxProgress').style.display = 'none';
                        window.rawFileData = allFeatures;
                        currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                        analyzedData = analyzeData(allFeatures, currentThreshold);
                        renderTable(analyzedData);
                    })
                    .catch(function(err) {
                        document.getElementById('ajaxProgress').style.display = 'none';
                        document.getElementById('result').innerHTML =
                            '<tr><td style="color:#ff6666;padding:15px;">AJAX scan error: ' + escapeHtml(err.message) + '</td></tr>';
                    });
            }

            function processChunk(chunks, idx, allFeatures, totalFiles, chunkSize) {
                if (_scanCancelled || idx >= chunks.length) { return Promise.resolve(); }

                var chunk = chunks[idx];
                var done  = Math.min(idx * chunkSize, totalFiles);
                var pct   = totalFiles > 0 ? Math.round(done / totalFiles * 100) : 0;

                document.getElementById('ajaxBar').style.width = pct + '%';
                document.getElementById('ajaxSubStatus').textContent =
                    'Chunk ' + (idx + 1) + '/' + chunks.length + ' \u2014 ' + done + '/' + totalFiles + ' files (' + pct + '%)';

                var body = new URLSearchParams();
                body.set('ajax_action', 'process');
                body.set('is_not_readable', chunk.isNotReadable ? '1' : '0');
                chunk.paths.forEach(function(p) { body.append('paths[]', p); });
                _seenHashes.forEach(function(h) { body.append('seen_hashes[]', h); });

                return fetch('', { method: 'POST', body: body })
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (_scanCancelled) { return; }
                        var feats = data.features || [];
                        feats.forEach(function(f) { allFeatures.push(f); });
                        if (data.new_hashes) {
                            data.new_hashes.forEach(function(h) { _seenHashes.push(h); });
                        }

                        // Incremental render every 3 chunks so user sees progress
                        if ((idx + 1) % 3 === 0 || idx + 1 === chunks.length) {
                            currentThreshold = parseFloat(document.getElementById('zThreshold').value) || 3.5;
                            analyzedData = analyzeData(allFeatures, currentThreshold);
                            renderTable(analyzedData);
                        }

                        return processChunk(chunks, idx + 1, allFeatures, totalFiles, chunkSize);
                    });
            }

            function cancelChunkedScan() {
                _scanCancelled = true;
                document.getElementById('ajaxProgress').style.display = 'none';
            }
            // ────────────────────────────────────────────────────────────────

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