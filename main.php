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
    if (empty($files)) return array();
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
    $readable = isset($result['file_readable']) ? $result['file_readable'] : array();
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
            //trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
        } else {
            return explode("\n", $content);
        }
    }

    // 2. Try file_get_contents
    if (function_exists('file_get_contents')) {
        $context = stream_context_create(array(
            'http' => array(
                'ignore_errors' => true, // Handle potential errors gracefully
                'header'  => implode("\r\n", array(
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
            //trigger_error("Failed to fetch URL using file_get_contents", E_USER_WARNING);
        }
    }

    // 3. Try file()
    if (function_exists('file')) {
        $content = @file($url, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($content !== false) {
            return $content;
        } else {
            //trigger_error("Failed to fetch URL using file()", E_USER_WARNING);
        }
    }

    // 4. No suitable method found
    //trigger_error("No suitable methods found to fetch URL content", E_USER_WARNING);
    return array();
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

// AJAX Backend
if (isset($_POST['ajax'])) {
    if ($_POST['ajax'] === 'prep') {
        $path = $_POST['dir'];
        $result = getSortedByPattern($path, $pattern);
        $fileReadable = $result['file_readable'];
        $fileNotReadable = $result['file_not_readable'];
        $allFiles = array_merge($fileReadable, $fileNotReadable);

        $whitelistMD5Sums = array();
        $blacklistMD5Sums = array();
        if (_WHITELIST_) {
            $whitelistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt');
            $whitelistMD5Sums = array_map('trim', $whitelistMD5Sums);
        }
        if (_BLACKLIST_) {
            $blacklistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt');
            $blacklistMD5Sums = array_map('trim', $blacklistMD5Sums);
        }

        echo json_encode(array(
            'files' => $allFiles,
            'whitelist' => $whitelistMD5Sums,
            'blacklist' => $blacklistMD5Sums
        ));
        exit;
    }

    if ($_POST['ajax'] === 'batch') {
        $files = json_decode($_POST['files'], true);
        $whitelist = json_decode($_POST['whitelist'], true);
        $blacklist = json_decode($_POST['blacklist'], true);
        $batch_results = array();

        foreach ($files as $filePath) {
            if (!is_readable($filePath)) {
                $mtime = @filemtime($filePath) ?: 0;
                $date = @date("Y-m-d H:i:s", $mtime);
                $batch_results[] = array(
                    'file'  => $filePath,
                    'sum'   => 'N/A',
                    'cmp'   => array('NOT_READABLE'),
                    'mtime' => $mtime,
                    'date' => $date
                );
                continue;
            }

            $fileSum = md5_file($filePath);
            if (in_array($fileSum, $whitelist)) continue;

            $mtime = filemtime($filePath);
            $date = @date("Y-m-d H:i:s", $mtime);

            if (in_array($fileSum, $blacklist)) {
                $batch_results[] = array(
                    'file' => $filePath,
                    'sum' => $fileSum,
                    'cmp' => array('BLACKLIST'),
                    'mtime' => $mtime,
                    'date' => $date
                );
                @unlink($filePath);
                continue;
            }

            if (pathinfo($filePath, PATHINFO_EXTENSION) == 'htaccess') {
                $filesize = filesize($filePath);
                $batch_results[] = array(
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
            $cmp = compareTokens($tokenNeedles, $tokens);
            $batch_results[] = array(
                'file' => $filePath,
                'sum' => $fileSum,
                'cmp' => $cmp,
                'mtime' => $mtime,
                'date' => $date
            );
        }
        echo json_encode($batch_results);
        exit;
    }
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
            /* dark gray background */
            color: #d0d0d0;
            /* light gray text */
            font-size: 14px;
        }

        table {
            border-spacing: 0;
            padding: 5px;
            border-radius: 5px;
            border: 1px solid #444;
            /* subtle border */
            width: 90%;
            margin: auto;
            background-color: #2a2a2a;
            /* darker table background */
        }

        tr,
        td {
            padding: 5px;
        }

        th {
            color: #f0f0f0;
            /* brighter header text */
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
            /* dark input bg */
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

        #result tr:nth-child(even) td {
            background: #242424;
            /* zebra striping */
        }

        #progress-container {
            width: 90%;
            margin: 10px auto;
            background: #333;
            display: none;
            border: 1px solid #444;
        }

        #progress-bar {
            width: 0%;
            height: 10px;
            background: #ff6666;
            transition: width 0.2s;
        }
    </style>
</head>

<body>
    <script>
        var results = [];
        var fileList = [];
        var whitelist = [];
        var blacklist = [];
        var duplicateTracker = {}; // Tracks hash -> path mapping
        var currentIdx = 0;
        var batchSize = 50;
        var essentialTokens = [
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

        function renderTable(list) {
            var html = "";
            for (var i = 0; i < list.length; i++) {
                var r = list[i];
                var cmpColored = r.cmp.map(function(token) {
                    if (essentialTokens.indexOf(token) !== -1) return '<span style="color:#ff8a03ff;">' + token + '</span>';
                    return token;
                }).join(", ");
                var cmpText = cmpColored.length ? " (" + cmpColored + ")" : "";
                var color = "#dddbdbff";
                if (r.cmp.indexOf("BLACKLIST") !== -1) color = "#f72f2fff";
                else if (r.cmp.indexOf("NOT_READABLE") !== -1) color = "#f72f2fff";
                else if (r.cmp.indexOf("HTACCESS") !== -1) color = "#66ccff";
                var extra = r.filesize !== undefined ? " (" + r.filesize.toFixed(1) + " Bytes)" : "";
                html += "<tr><td style='color:" + color + "; font-size:14px;'>" +
                    r.file + cmpText + " (" + r.date + ")" + extra + " (" + r.sum + ")" +
                    "</td></tr>";
            }
            document.getElementById("result").innerHTML = html;
        }

        function copyResults() {
            var text = results.map(function(r) {
                var cmp = r.cmp.length ? " (" + r.cmp.join(", ") + ")" : "";
                return r.file + cmp + " (" + r.date + ") (" + r.sum + ")";
            }).join("\n");
            var textArea = document.createElement("textarea");
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert("Results copied to clipboard!");
        }

        function sortResults(mode) {
            if (mode === "tokens") {
                results.sort(function(a, b) {
                    if (b.cmp.length !== a.cmp.length) return b.cmp.length - a.cmp.length;
                    return b.mtime - a.mtime;
                });
            } else if (mode === "mtime") {
                results.sort(function(a, b) { return b.mtime - a.mtime; });
            }
            renderTable(results);
        }

        function postAjax(data, success, error) {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.href, true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    if (xhr.status === 200) {
                        try {
                            success(JSON.parse(xhr.responseText));
                        } catch (e) { error("Parse error"); }
                    } else { error(xhr.status); }
                }
            };
            var body = [];
            for (var key in data) body.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
            xhr.send(body.join('&'));
        }

        function startScan() {
            var dir = document.getElementsByName('dir')[0].value;
            var btn = document.getElementById('search-btn');
            btn.disabled = true;
            btn.value = "SCANNING...";
            document.getElementById('progress-container').style.display = 'block';
            document.getElementById('res-header').style.display = 'table-row';
            postAjax({ ajax: 'prep', dir: dir }, function(data) {
                fileList = data.files;
                whitelist = data.whitelist;
                blacklist = data.blacklist;
                currentIdx = 0;
                results = [];
                duplicateTracker = {};
                processNextBatch();
            }, function(err) { btn.disabled = false; btn.value = "SEARCH"; });
        }

        function processNextBatch() {
            if (currentIdx >= fileList.length) {
                document.getElementById('search-btn').disabled = false;
                document.getElementById('search-btn').value = "SEARCH";
                return;
            }
            var batch = fileList.slice(currentIdx, currentIdx + batchSize);
            postAjax({
                ajax: 'batch',
                files: JSON.stringify(batch),
                whitelist: JSON.stringify(whitelist),
                blacklist: JSON.stringify(blacklist)
            }, function(batchResults) {
                for (var i = 0; i < batchResults.length; i++) {
                    var r = batchResults[i];
                    if (r.sum !== 'N/A' && r.cmp.indexOf('BLACKLIST') === -1) {
                        if (duplicateTracker[r.sum]) {
                            r.cmp = [duplicateTracker[r.sum]]; // Original behavior: show the path it duplicates
                        } else {
                            duplicateTracker[r.sum] = r.file;
                        }
                    }
                    results.push(r);
                }
                currentIdx += batchSize;
                var pct = Math.min(100, Math.floor((currentIdx / fileList.length) * 100));
                document.getElementById('progress-bar').style.width = '100%';
                sortResults('mtime');
                processNextBatch();
            }, function(err) {
                console.log("Retry batch...");
                setTimeout(processNextBatch, 2000);
            });
        }
    </script>
    <form method="post" onsubmit="event.preventDefault(); startScan();">
        <table align="center" width="30%">
            <tr><th>Sussy Finder</th></tr>
            <tr><td><input type="text" name="dir" value="<?= getcwd() ?>"></td></tr>
            <tr><td><input type="submit" id="search-btn" value="SEARCH"></td></tr>
        </table>
        <div id="progress-container"><div id="progress-bar"></div></div>
        <table align="center" style="margin-top: 10px;">
            <tr id="res-header" style="display:none;">
                <td>
                    <span style="font-weight:bold;font-size:25px;">RESULT</span><br>
                    <button type="button" onclick="copyResults()">Copy Results</button>
                    <button type="button" onclick="sortResults('tokens')">Sort by Tokens</button>
                    <button type="button" onclick="sortResults('mtime')">Sort by Time</button>
                </td>
            </tr>
        </table>
        <table align="center"><tbody id="result"></tbody></table>
    </form>
</body>
</html>
