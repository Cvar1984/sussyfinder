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

    // Get the file tokens
    $tokens = @token_get_all($fileContent); // https://www.php.net/manual/en/function.token-get-all.php

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
    if (function_exists('file_get_contents')) {
        $context = stream_context_create([
            'http' => [
                'ignore_errors' => true, // Handle potential errors gracefully
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $content = @file_get_contents($url, false, $context);

        if ($content !== false) {
            return explode("\n", $content);
        } else {
            trigger_error("Failed to fetch URL using file_get_contents", E_USER_WARNING);
        }
    }

    // 3. Try file()
    if (function_exists('file')) {
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

function output($array) {
    header("Content-Type: text/plain");
    header("Cache-Control: no-cache");
    header("Pragma: no-cache");
    echo json_encode($array, JSON_PRETTY_PRINT);
    die();
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $request = json_decode(file_get_contents('php://input'), true);
    $path = $request['dir'];

    if (!is_dir($path)) {
        output([
            'success'=> false,
            'message' => "There are no files in <span class='underline italic'>{$path}</span>."
        ]);
    }

    $result = getSortedByPattern($path, $pattern);
    $fileReadable = sortByLastModified($result['file_readable']);
    $fileNotReadable = $result['file_not_readable'];
    $duplicateFiles = array();
    $results = array();

    foreach ($fileReadable as $filePath) {
        $fileSum = md5_file($filePath);
        if (in_array($fileSum, $whitelistMD5Sums)) continue;

        if (in_array($fileSum, $blacklistMD5Sums)) {
            $mtime = filemtime($filePath);
            $date = @date("Y-m-d H:i:s", $mtime);
            $results[] = array(
                'file' => $filePath,
                'sum' => $fileSum,
                'cmp' => array('BLACKLIST'),
                'mtime' => $mtime,
                'date' => $date
            );
            unlink($filePath);
            continue;
        }
        if (($duplicatePath = array_search($fileSum, $duplicateFiles)) !== false) {
            $mtime = filemtime($filePath);
            $date = @date("Y-m-d H:i:s", $mtime);
            $results[] = array(
                'file' => $filePath,
                'sum' => $fileSum,
                'cmp' => array("$duplicatePath"),
                'mtime' => $mtime,
                'date' => $date
            );
            continue;
        }
        $duplicateFiles[$filePath] = $fileSum;

        if (pathinfo($filePath, PATHINFO_EXTENSION) == 'htaccess') {
            $mtime = filemtime($filePath);
            $date = @date("Y-m-d H:i:s", $mtime);
            $filesize = filesize($filePath);
            $results[] = array(
                'file' => $filePath,
                'sum' => $fileSum,
                'cmp' => array('HTACCESS'),
                'mtime' => $mtime,
                'date' => $date,
                'filesize' => $filesize
            );
            continue;
        }

        $tokens = getFileTokens($filePath);
        $cmp = compareTokens($tokens, $tokenNeedles);
        $mtime = filemtime($filePath);
        $date = @date("Y-m-d H:i:s", $mtime);
        $results[] = array(
            'file' => $filePath,
            'sum' => $fileSum,
            'cmp' => $cmp,
            'mtime' => $mtime,
            'date' => $date
        );
    }
    foreach ($fileNotReadable as $filePath) {
        if (!($mtime = @filemtime($filePath))) {
            $mtime = 0;
        }
        $date = @date("Y-m-d H:i:s", $mtime);
        $results[] = array(
            'file'  => $filePath,
            'sum'   => 'N/A',
            'cmp'   => array('NOT_READABLE'),
            'mtime' => $mtime,
            'date' => $date
        );
    }
    output([
        'success' => true,
        'results'=> $results
    ]);
}


?>
<!DOCTYPE html>
<html lang="en-us">

<head>
    <title>Sussy Finder</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style type="text/tailwindcss">
        @theme {
            --color-base: #1e1e1e;
            --color-soft: #d0d0d0;
            --color-dark: #2a2a2a;
            --color-darker: #363535;
            --color-accent: #ff6666;
        }
        
        body {
            font-family: 'Ubuntu Mono', monospace;
            background-color: var(--color-base);
            /* dark gray background */
            color: var(--color-soft);
            /* light gray text */
            font-size: 14px;
            @apply py-10 px-5;
        }

        tr,
        td {
            @apply p-5 text-[14px];
        }

        th {
            @apply text-start;
            color: #f0f0f0;
            /* brighter header text */
            padding: 5px;
            font-size: 20px;
        }

        /* Results table */
        #result td {
            font-size: 12px;
            padding: 3px 6px;
            line-height: 1.3em;
            border-bottom: 1px solid #333;
            /* subtle divider */
            white-space: normal;
            word-wrap: break-word;
            overflow-wrap: anywhere;
            max-width: 95vw;
        }
    </style>
</head>

<body>
    <div class="bg-dark rounded-xl p-5 mx-auto w-[90%] flex flex-col gap-2">
        <div class="flex items-center justify-center gap-2">
            <h1 class="text-5xl font-bold my-5 mb-7">Sussy Finder</h1>
        </div>
        <input type="text" id="dir" class="w-full bg-darker rounded-lg p-3 w-full outline-none focus:outline-none focus:ring-2 focus:ring-accent" value="<?= getcwd() ?>">
        <button type="button" class="w-full bg-accent mt-3 rounded-lg font-bold p-3 w-full outline-none focus:outline-none focus:ring-2 focus:ring-accent hover:cursor-pointer" onclick="submitForm()">SEARCH</button>
        
        <div id="alert" class="hidden my-3"></div>

        <!-- Progress Bar -->
        <div id="progressSection" class="mt-3 hidden w-full">
            <div class="bg-darker rounded-lg p-3">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-sm">Scanning files...</span>
                    <span id="progressText" class="text-sm">0%</span>
                </div>
                <div class="w-full bg-base rounded-full h-2">
                    <div id="progressBar" class="bg-accent h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                </div>
            </div>
        </div>

        <div id="resultsSection" class="hidden w-full">
            <div class="flex justify-end my-5 gap-1">
                <button type="button" class="bg-darker p-2 rounded-lg hover:bg-darker/50 hover:cursor-pointer" onclick="copyResults()">Copy Results</button>
                <button type="button" class="bg-darker p-2 rounded-lg hover:bg-darker/50 hover:cursor-pointer" onclick="sortResults('tokens')">Sort by Tokens</button>
                <button type="button" class="bg-darker p-2 rounded-lg hover:bg-darker/50 hover:cursor-pointer" onclick="sortResults('mtime')">Sort by Time</button>
            </div>

            <div class="w-full">
                <div class="grid grid-cols-[20ch_1fr_1fr_30ch] gap-x-3 py-2">
                    <div class="text-start">Date</div>
                    <div class="text-start">Path</div>
                    <div class="text-start">Token</div>
                    <div class="text-start">md5sum</div>
                </div>
                <div id="result" class="text-[14px]"></div>
            </div>
            
            <!-- Detail Modal -->
            <div id="detailModal" class="hidden fixed inset-0 bg-black/60 z-50 items-center justify-center">
                <div class="bg-dark rounded-xl p-5 w-[90vw] max-w-[900px] max-h-[80vh] overflow-auto">
                    <div class="flex items-center justify-between mb-4">
                        <h2 class="text-2xl font-bold">Details</h2>
                        <button type="button" class="bg-darker rounded-full text-xl font-bold px-3 py-1 hover:bg-darker/60 hover:cursor-pointer" onclick="closeModal()">&times;</button>
                    </div>
                    <div id="modalContent" class="text-[14px] space-y-2"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let results = []; // will be filled from PHP
        let getActiveType = localStorage.getItem('sort') || 'mtime';
        let essentialTokens = [
            'base64_decode',
            'str_rot13',
            'bin2hex',
            'hex2bin',
            'goto',
            'eval',
            'exec',
            'shell_exec',
            'system',
            'passthru',
            'pcntl_fork',
            'fsockopen',
            'proc_open',
            'popen ',
            'posix_kill',
            'posix_setpgid',
            'posix_setsid',
            'posix_setuid',
            'fopen',
            'fsockopen',
            'file_put_contents',
            'file_get_contents',
            'url_get_contents',
            'move_uploaded_file',
            '$_files',
            '$auth_pass',
            '$password',
            '$pass',
            '$SISTEMIT_COM_ENC',
        ];

        const sortByTokensBtn = document.querySelector('button[onclick="sortResults(\'tokens\')"]');
        const sortByTimeBtn = document.querySelector('button[onclick="sortResults(\'mtime\')"]');

        setActiveBtn(getActiveType);
        
        function setActiveBtn(type) {
            if (type === 'tokens') {
                localStorage.setItem('sort', 'tokens');
                sortByTimeBtn.classList.remove('ring-2', 'ring-accent');
                sortByTokensBtn.classList.add('ring-2', 'ring-accent');
            } else if (type === 'mtime') {
                localStorage.setItem('sort', 'mtime');
                sortByTokensBtn.classList.remove('ring-2', 'ring-accent');
                sortByTimeBtn.classList.add('ring-2', 'ring-accent');
                
            }
        }

        function renderTable(list) {
            let html = "";
            for (let i = 0; i < list.length; i++) {
                let r = list[i];

                // Colorize tokens inside cmp array
                let cmpColored = r.cmp.map(token => {
                    if (essentialTokens.includes(token)) {
                        return `<span style="color:#ff8a03ff;">${token}</span>`;
                    }
                    return token;
                }).join(", ");

                let color = "#dddbdbff";
                if (r.cmp.includes("BLACKLIST")) color = "#f72f2fff";
                else if (r.cmp.includes("NOT_READABLE")) color = "#f72f2fff";
                else if (r.cmp.includes("HTACCESS")) color = "#66ccff";

                // add filesize only if exists
                let extra = r.filesize !== undefined ? " (" + r.filesize.toFixed(1) + " Bytes)" : "";

                html += `<div class="grid grid-cols-[20ch_1fr_1fr_30ch] gap-x-3 odd:bg-transparent even:bg-[#242424] py-2 hover:bg-darker/60 cursor-pointer" onclick="showModal(${i})">
                             <div class='text-[${color}] whitespace-nowrap'><div class="truncate" title="${r.date}">${r.date}</div></div>
                             <div class='text-[${color}] min-w-0'>
                                <div class="w-full truncate" title="${r.file + extra}">${r.file + extra}</div>
                            </div>
                             <div class='text-[${color}] min-w-0'>
                                <div class="w-full truncate" title="${r.cmp.join(', ')}">${cmpColored}</div>
                            </div>
                             <div class='text-[${color}] whitespace-nowrap'><div class="truncate" title="${r.sum}">${r.sum}</div></div>
                         </div>`;
            }
            document.getElementById("result").innerHTML = html;
        }

        function copyResults() {
            let text = results.map(r => {
                let cmp = r.cmp.length ? " (" + r.cmp.join(", ") + ")" : "";
                let extra = r.filesize !== undefined ? " (" + r.filesize.toFixed(1) + " Bytes)" : "";
                return r.file + cmp + " (" + r.date + ")" + extra + " (" + r.sum + ")";
            }).join("\n");

            navigator.clipboard.writeText(text)
                .then(() => alert("Results copied to clipboard!"))
                .catch(() => alert("Failed to copy results."));
        }

        function sortResults(mode) {
            if (mode === "tokens") {
                results.sort((a, b) => {
                    if (b.cmp.length !== a.cmp.length) return b.cmp.length - a.cmp.length;
                    return b.mtime - a.mtime;
                });
            } else if (mode === "mtime") {
                results.sort((a, b) => b.mtime - a.mtime);
            }

            setActiveBtn(mode);
            renderTable(results);
        }

        function copyResults() {
            let text = results.map(r => {
                let cmp = r.cmp.length ? " (" + r.cmp.join(", ") + ")" : "";
                return r.file + cmp + " (" + r.sum + ")";
            }).join("\n");

            navigator.clipboard.writeText(text)
                .then(() => alert("Results copied to clipboard!"))
                .catch(() => alert("Failed to copy results."));
        }

        function submitForm() {
            let dir = document.getElementById("dir").value;
            
            // Show progress bar and hide other sections
            document.getElementById("progressSection").classList.remove("hidden");
            document.getElementById("resultsSection").classList.add("hidden");
            document.getElementById("alert").classList.add("hidden");
            
            // Start progress animation
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 15;
                if (progress > 90) progress = 90;
                updateProgress(progress);
            }, 200);
            
            fetch("", {
                method: "POST",
                body: JSON.stringify({ dir: dir })
            }).then(response => response.json()).then(data => {
                // Complete progress
                clearInterval(progressInterval);
                updateProgress(100);
                
                // Hide progress after a short delay
                setTimeout(() => {
                    document.getElementById("progressSection").classList.add("hidden");
                    
                    if (data.success) {
                        results = data.results;
                        renderTable(results);
                        sortResults(getActiveType);
                        document.getElementById("resultsSection").classList.remove("hidden");
                    } else {
                        results = [];
                        document.getElementById("resultsSection").classList.add('hidden');
                        const alert = document.getElementById('alert');
                        alert.classList.remove('hidden');
                        alert.innerHTML = data.message ? `<h1 class='text-xl'>${data.message}</h1>` : null;
                    }
                }, 500);
            }).catch(error => {
                clearInterval(progressInterval);
                document.getElementById("progressSection").classList.add("hidden");
                const alert = document.getElementById('alert');
                alert.classList.remove('hidden');
                alert.innerHTML = "Error: " + error.message;
            });
        }
        
        function updateProgress(percent) {
            document.getElementById("progressBar").style.width = percent + "%";
            document.getElementById("progressText").textContent = Math.round(percent) + "%";
        }
        
        function showModal(index) {
            const r = results[index];
            if (!r) return;
            const extra = r.filesize !== undefined ? ` (${r.filesize.toFixed(1)} Bytes)` : "";
            // Colorize tokens like in the table
            const cmpColored = (Array.isArray(r.cmp) ? r.cmp : [r.cmp])
                .map(token => {
                    if (essentialTokens.includes(token)) {
                        return `<span class='text-[#ff8a03ff]'>${token}</span>`;
                    }
                    return token;
                }).join(", ");

            const content = `
                <div class="space-y-4">
                    <div class="bg-darker rounded-lg p-4">
                        <h3 class="text-lg font-semibold mb-3 text-accent">File Information</h3>
                        <div class="space-y-2">
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">Date:</span>
                                <span class="text-soft ml-2">${r.date}</span>
                            </div>
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">Path:</span>
                                <span class="text-soft ml-2 break-all">${r.file}${extra}</span>
                            </div>
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">Size:</span>
                                <span class="text-soft ml-2">${r.filesize ? r.filesize.toFixed(1) + ' Bytes' : 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-darker rounded-lg p-4">
                        <h3 class="text-lg font-semibold mb-3 text-accent">Security Analysis</h3>
                        <div class="space-y-2">
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">md5sum:</span>
                                <a href='https://www.virustotal.com/gui/file/${r.sum}' class="text-[#ff8a03ff] hover:underline ml-2 font-mono text-sm break-all" target='_blank'>${r.sum}</a>
                            </div>
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">Tokens:</span>
                                <div class="ml-2 flex-1">
                                    ${r.cmp.length > 0 ? 
                                        `<div class="flex flex-wrap gap-1">${cmpColored}</div>` : 
                                        '<span class="text-gray-500 italic">No suspicious tokens found</span>'
                                    }
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    ${r.cmp.length > 0 ? `
                    <div class="bg-darker rounded-lg p-4">
                        <h3 class="text-lg font-semibold mb-3 text-accent">Risk Assessment</h3>
                        <div class="space-y-2">
                            <div class="flex items-center">
                                <span class="font-medium text-soft w-20">Risk Level:</span>
                                <span class="ml-2 px-2 py-1 rounded text-sm font-medium ${r.cmp.includes('BLACKLIST') ? 'bg-red-900 text-red-200' : 
                                    r.cmp.includes('NOT_READABLE') ? 'bg-red-900 text-red-200' : 
                                    r.cmp.includes('HTACCESS') ? 'bg-blue-900 text-blue-200' : 
                                    'bg-yellow-900 text-yellow-200'}">
                                    ${r.cmp.includes('BLACKLIST') ? 'HIGH - BLACKLISTED' : 
                                      r.cmp.includes('NOT_READABLE') ? 'HIGH - NOT READABLE' : 
                                      r.cmp.includes('HTACCESS') ? 'MEDIUM - HTACCESS' : 
                                      'MEDIUM - SUSPICIOUS TOKENS'}
                                </span>
                            </div>
                            <div class="flex items-start">
                                <span class="font-medium text-soft w-20">Count:</span>
                                <span class="text-soft ml-2">${r.cmp.length} suspicious token${r.cmp.length !== 1 ? 's' : ''}</span>
                            </div>
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
            document.getElementById('modalContent').innerHTML = content;
            const modal = document.getElementById('detailModal');
            modal.classList.remove('hidden');
            modal.classList.add('flex');

            // Close on backdrop click
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeModal();
            }, { once: true });

            // Close on ESC
            document.addEventListener('keydown', escHandler, { once: true });
        }

        function escHandler(e) {
            if (e.key === 'Escape') closeModal();
        }

        function closeModal() {
            const modal = document.getElementById('detailModal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    

    </script>
</body>

</html>