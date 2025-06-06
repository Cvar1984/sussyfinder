<?php

/**
Written by Cvar1984 <Cvar1984@pm.me>, November 2022
Copyright (C) 2022  Cvar1984

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

$minute = 60;
$limit = (60 * $minute); // 60 (seconds) = 1 Minutes
ini_set('memory_limit', '-1');
ini_set('max_execution_time', $limit);
set_time_limit($limit);
ini_set('display_errors', 1); // debug
define('_DEBUG_', true);
define('_WHITELIST_', false);
define('_BLACKLIST_', true);
define('_VTOTAL_', false);

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
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // Disable strict peer verification (caution in production)
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
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

        // Check if it's a symlink
        if (is_link($entryPath)) {
            $entries['symlink'][] = $entryPath;

            // Get the actual symlink target
            $symlinkTarget = readlink($entryPath);
            $resolvedTarget = realpath($symlinkTarget);

            // Follow the symlink only if it's a directory and hasn't been visited
            if ($resolvedTarget && is_dir($resolvedTarget) && !isset($visited[$resolvedTarget])) {
                recursiveScan($resolvedTarget, $entries, $visited);
            }
            continue; // Continue processing other files
        }

        // Store whether it's a directory to avoid redundant calls
        $isDir = is_dir($entryPath);

        // If it's a directory, recursively scan it
        if ($isDir) {
            recursiveScan($entryPath, $entries, $visited);
        } elseif (is_readable($entryPath)) {
            // Add readable files
            $entries['file_readable'][] = $entryPath;
        } else {
            // Add non-readable files
            $entries['file_not_readable'][] = $entryPath;
        }
    }

    // Close the directory
    closedir($handle);

    // Return the entries array
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
    // Get the writable and non-writable files from the directory
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

    // Sort the writable files by their last modified time
    $readable = sortByLastModified($readable);

    // Return the sorted files
    return array(
        'file_readable' => $readable,
        'file_not_readable' => $notReadable,
    );
}

/**
 * Recursively list a file by descending modified time and extension.
 *
 * @param string $path The directory path to scan.
 * @param array $ext An array of file extensions to filter.
 * @return array An associative array containing two keys: 'file_readable' and 'file_not_readable'.
 *               Each key contains an array of file paths, sorted by their last modified time.
 */
function getSortedByExtension($path, $ext)
{
    $result = getSortedByTime($path);
    $fileReadable = $result['file_readable'];
    //isset($result['file_not_readable']) ? $result['file_not_readable'] : false;

    foreach ($fileReadable as $entry) {
        $pathinfo = pathinfo($entry, PATHINFO_EXTENSION);

        if (in_array($pathinfo, $ext)) {
            $sortedWritableFile[] = $entry;
        }
    }
    if (isset($fileNotWritable)) {
        foreach ($fileNotWritable as $entry) {
            $pathinfo = pathinfo($entry, PATHINFO_EXTENSION);

            if (in_array($pathinfo, $ext)) {
                $sortedNotWritableFile[] = $entry;
            }
        }
    } else {
        $sortedNotWritableFile = false;
    }
    return array(
        'file_readable' => $sortedWritableFile,
        'file_not_readable' => $sortedNotWritableFile
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
        $patterns;

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

    // Get the file tokens
    $tokens = token_get_all($fileContent);

    // Create an output array
    $output = array();

    // Iterate over the tokens and add the token types to the output array

    foreach ($tokens as $token) {
        //$output[] = is_array($token) ? $token[1] : $token;

        if (is_array($token)) {
            $output[] = $token[1];
        } else {
            $output[] = $token;
        }
    }

    // Remove any duplicate or empty tokens from the output array
    $output = array_values(array_unique(array_filter(array_map("trim", $output))));

    // Return the output array
    return $output;
}
/**
 * recursively search for a specific case within an array, including nested arrays.
 *
 * @param string $needle
 * @param array $haystack
 * @return array
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
 * Return array of string from url
 *
 * @param string $url
 * @return array
 */
function urlFileArray($url)
{
    if (isset($GLOBALS['ch'])) {
        curl_setopt($GLOBALS['ch'], CURLOPT_URL, $url);
        // Handle potential cURL errors
        if (curl_errno($GLOBALS['ch'])) {
            $error_msg = curl_error($GLOBALS['ch']);
            //curl_close($GLOBALS['ch']);
            trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
            return array();
        }

        $content = curl_exec($GLOBALS['ch']);
        //curl_close($GLOBALS['ch']);
        return explode("\n", $content);
    } else if (isWorking('file_get_contents')) {
        $context = stream_context_create(
            array(
                'http' => array(
                    'ignore_errors' => true, // Handle potential errors gracefully
                ),
                'ssl' => array(
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                )
            )
        );

        $content = @file_get_contents($url, false, $context); // Use error suppression for cleaner handling

        // If file_get_contents fails, return false
        if ($content === false) {
            trigger_error("Failed to fetch URL using file_get_contents", E_USER_WARNING);
            return array();
        }

        return explode("\n", $content);
    } else if (isWorking('file')) {
        $content = @file($url, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); // Use error suppression for cleaner handling

        // If file() fails, return false
        if ($content === false) {
            trigger_error("Failed to fetch URL using file", E_USER_WARNING);
            return array();
        }

        return $content;
    }

    trigger_error("No suitable methods found to fetch URL content", E_USER_WARNING);
    return array();
}
/**
 * Get Online Vibes check fr, return gyatt if L
 *
 * @param string $hashSum
 * @param string $APIKey
 * @return array|bool|null
 */
function vTotalCheckHash($hashSum, $APIKey)
{

    if (!isset($GLOBALS['ch']) || empty($APIKey)) {
        return false;
    }

    curl_setopt($GLOBALS['ch'], CURLOPT_URL, sprintf('https://www.virustotal.com/api/v3/files/%s', $hashSum));
    curl_setopt($GLOBALS['ch'], CURLOPT_HTTPHEADER, array(sprintf('x-apikey: %s', $APIKey)));
    if (curl_errno($GLOBALS['ch'])) {
        $error_msg = curl_error($GLOBALS['ch']);
        //curl_close($GLOBALS['ch']);
        trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
        return false;
    }
    $result = curl_exec($GLOBALS['ch']);
    return json_decode($result, true);
}


$APIKey = array(
    '',
);

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
    '`',

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
if (count($argv) < 2) {
    printf('php %s /path/to/dir%s', $argv[0], PHP_EOL);
    return;
}

$path = $argv[1];
$result = getSortedByPattern($path, $pattern);

$fileReadable = $result['file_readable'];
$fileNotWritable = $result['file_not_readable'];
$fileReadable = sortByLastModified($fileReadable);

$currentKeyIndex = 0;
$actionCount = 0;
$duplicateFiles = array();

foreach ($fileReadable as $filePath) {
    $fileSum = md5_file($filePath);

    if (in_array($fileSum, $whitelistMD5Sums)) { // if in whitelist skip
        continue;
    } elseif (in_array($fileSum, $blacklistMD5Sums)) { // if in blacklist alert and remove
        printf("\033[31m%s (Blacklist)(%s)\033[0m\n", $filePath, $fileSum);
        unlink($filePath);
        continue;
    } elseif (($duplicatePath = array_search($fileSum, $duplicateFiles)) !== false) {
        printf("\033[90m%s -> %s(%s)\033[0m\n", $filePath, $duplicatePath, $fileSum);
        continue;
    }

    $duplicateFiles[$filePath] = $fileSum;

    if (_VTOTAL_) {
        $vTotalRes = vTotalCheckHash($fileSum, $APIKey[$currentKeyIndex]);

        $actionCount++;

        // keep track of the number of actions performed within a loop
        //if ($actionCount >= 240) {
        if ($actionCount >= 1) {
            $currentKeyIndex = ($currentKeyIndex + 1) % count($APIKey);
            $actionCount = 0;
        }

        if (isset($vTotalRes['data'])) {
            $matchedString = inStringArray('malicious', $vTotalRes); // matching casecmp
            if (!empty($matchedString)) {
                printf("\033[31m[!] %s (VTotal Webshell) (%s)\033[0m\n", $filePath, $fileSum);
                unlink($filePath);
                continue;
            } else if ($vTotalRes['data']['attributes']['total_votes']['malicious'] > 0) {
                printf("\033[33m[!] %s (VTotal Malicious) (%s)\033[0m\n", $filePath, $fileSum);
                //unlink($filePath);
                continue;
            }
        }
    }

    $tokens = getFileTokens($filePath);
    $cmp = compareTokens($tokens, $tokenNeedles);
    $cmp = implode(', ', $cmp);

    if (!empty($cmp)) {
        printf("\033[90m%s (%s)\033[0m\n", $filePath, $cmp);
    }
}
