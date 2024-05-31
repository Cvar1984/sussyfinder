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
/**
 * Recursive listing files
 *
 * @param string $directory
 * @param array $entries_array optional
 * @return array of files
 */
function recursiveScan($directory, &$entries_array = array()) // :array
{
    // Check if the directory exists and is readable
    if (!is_dir($directory) || !is_readable($directory)) {
        return $entries_array;
    }

    // Open the directory
    $handle = opendir($directory);
    if (!$handle) {
        return $entries_array;
    }

    // Iterate over the directory contents
    while (($entry = readdir($handle)) !== false) {
        // Skip the current directory and parent directory
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        // Get the full path to the entry
        $entryPath = $directory . DIRECTORY_SEPARATOR . $entry;

        // Check if the entry is a symlink
        if (is_link($entryPath)) {
            continue;
        }

        // Check if the entry is a directory
        if (is_dir($entryPath)) {
            // Recursively scan the directory
            $entries_array = recursiveScan($entryPath, $entries_array);
        } elseif (is_readable($entryPath)) {
            // Add the file to the writable array
            $entries_array['file_readable'][] = $entryPath;
        } else {
            // Add the file to the non-writable array
            $entries_array['file_not_readable'][] = $entryPath;
        }
    }

    // Close the directory
    closedir($handle);

    // Return the entries array
    return $entries_array;
}

/**
 *
 * Sort array of list file by lastest modified time
 *
 * @param array  $files Array of files
 *
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
 *
 * @return array
 *
 */
function getSortedByTime($path)// :array
{
    // Get the writable and non-writable files from the directory
    $result = recursiveScan($path);
    $readable = $result['file_readable'];
    $notReadable = isset($result['file_not_readable']) ? $result['file_not_readable'] : array();

    // Sort the writable files by their last modified time
    $readable = sortByLastModified($readable);

    // Return the sorted files
    return array(
        'file_readable' => $readable,
        'file_not_readable' => $notReadable,
    );
}

/**
 * Recurisively list a file by array of extension
 *
 * @param string $path
 * @param array $ext
 * @return array of files
 */
function getSortedByExtension($path, $ext)
{
    $result = getSortedByTime($path);
    $fileReadable = $result['file_readable'];
    isset($result['file_not_readable']) ? $result['file_not_readable'] : false;

    foreach ($fileReadable as $entry) {
        $pathinfo = pathinfo($entry, PATHINFO_EXTENSION);
        $pathinfo = strtolower($pathinfo);

        if (in_array($pathinfo, $ext)) {
            $sortedWritableFile[] = $entry;
        }
    }
    if (isset($fileNotWritable)) {
        foreach ($fileNotWritable as $entry) {
            $pathinfo = pathinfo($entry, PATHINFO_EXTENSION);
            $pathinfo = strtolower($pathinfo);

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
 * Get lowercase Array of tokens in a file
 *
 * @param string $filename
 * @return array
 */
function getFileTokens($filename)
{
    // Replace short PHP tags with PHP tags
    $fileContent = file_get_contents($filename);
    $fileContent = preg_replace('/<\?([^p=\w])/m', '<?php ', $fileContent);

    // Get the file tokens
    $tokens = token_get_all($fileContent);

    // Create an output array
    $output = array();

    // Iterate over the tokens and add the token types to the output array

    foreach ($tokens as $token) {
        $output[] = strtolower(is_array($token) ? $token[1] : $token);
    }

    // Remove any duplicate or empty tokens from the output array
    $output = array_values(array_unique(array_filter(array_map("trim", $output))));

    // Return the output array
    return $output;
}
/**
 * inStringArray
 *
 * @param string $needle
 * @param array $haystack
 * @return bool
 */
function inStringArray($needle, $haystack)
{
    $matches = [];
    foreach ($haystack as $key => $value) {
        if (is_string($value)) {
            // Check if string is found
            if (strpos($value, $needle) !== false) {
                $matches[] = $key; // Add key to matches
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
 * @return array|false
 */
function urlFileArray($url)
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE); // Disable strict peer verification (caution in production)
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);

        // Handle potential cURL errors
        if (curl_errno($ch)) {
            $error_msg = curl_error($ch);
            curl_close($ch);
            trigger_error("cURL error fetching URL: $error_msg", E_USER_WARNING);
            return false;
        }

        $content = curl_exec($ch);
        curl_close($ch);
        return explode("\n", $content);
    } else if (function_exists('file_get_contents')) {
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
            return false;
        }

        return explode("\n", $content);
    } else if (function_exists('file')) {
        $content = @file($url, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); // Use error suppression for cleaner handling

        // If file() fails, return false
        if ($content === false) {
            trigger_error("Failed to fetch URL using file", E_USER_WARNING);
            return false;
        }

        return $content;
    }

    trigger_error("No suitable methods found to fetch URL content", E_USER_WARNING);
    return false;
}
/**
 * Get Online Vibes check, return gyatt if fail
 *
 * @param string $hashSum
 * @return array|null
 */
function vTotalCheckHash($hashSum)
{
    $APIKey = '';

    if (!function_exists('curl_init') || empty($APIKey)) {
        return false;
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, sprintf('https://www.virustotal.com/api/v3/files/%s', $hashSum));
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(sprintf('x-apikey: %s', $APIKey)));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);

    return json_decode($result, true);

}

$ext = array(
    'php',
    'phps',
    'pht',
    'phpt',
    'phtm',
    'phtml',
    'phar',
    'php3',
    'php4',
    'php5',
    'php7',
    'shtml',
    'suspected'
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
);

$whitelistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt');
$blacklistMD5Sums = urlFileArray('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt');
?>
<!DOCTYPE html>
<html lang="en-us">

    <head>
        <title>Sussy Finder</title>
        <style type="text/css">
            @import url('https://fonts.googleapis.com/css?family=Ubuntu+Mono&display=swap');

            body {
                font-family: 'Ubuntu Mono', monospace;
                color: #8a8a8a;
            }

            table {
                border-spacing: 0;
                padding: 10px;
                border-radius: 7px;
                border: 3px solid #d6d6d6;
            }

            tr,
            td {
                padding: 7px;
            }

            th {
                color: #8a8a8a;
                padding: 7px;
                font-size: 25px;
            }

            input[type=submit]:focus {
                background: #ff9999;
                color: #fff;
                border: 3px solid #ff9999;
            }

            input[type=submit]:hover {
                border: 3px solid #ff9999;
                cursor: pointer;
            }

            input[type=text]:hover {
                border: 3px solid #ff9999;
            }

            input {
                font-family: 'Ubuntu Mono', monospace;
            }

            input[type=text] {
                border: 3px solid #d6d6d6;
                outline: none;
                padding: 7px;
                color: #8a8a8a;
                width: 100%;
                border-radius: 7px;
            }

            input[type=submit] {
                color: #8a8a8a;
                border: 3px solid #d6d6d6;
                outline: none;
                background: none;
                padding: 7px;
                width: 100%;
                border-radius: 7px;
            }
        </style>
    </head>

    <body>
        <script type="text/javascript">
            function copytable(el) {
                var urlField = document.getElementById(el)
                var range = document.createRange()
                range.selectNode(urlField)
                window.getSelection().addRange(range)
                document.execCommand('copy')
            }
        </script>
        <form method="post">
            <table align="center" width="30%">
                <tr>
                    <th>
                        Sussy Finder
                    </th>
                </tr>
                <tr>
                    <td>
                        <input type="text" name="dir" value="<?= getcwd() ?>">
                    </td>
                </tr>
                <tr>
                    <td>
                        <input type="submit" name="submit" value="SEARCH">
                    </td>
                </tr>

                <?php if (isset($_POST['submit'])) { ?>
                    <tr>
                        <td>
                            <span style="font-weight:bold;font-size:25px;">RESULT</span>
                            <input type=button value="Copy to Clipboard" onClick="copytable('result')">
                        </td>
                    </tr>
                </table>
                <table id="result" align="center" width="30%">
                    <?php
                    $path = $_POST['dir'];
                    $result = getSortedByExtension($path, $ext);

                    $fileReadable = $result['file_readable'];
                    $fileNotWritable = $result['file_not_readable'];
                    $fileReadable = sortByLastModified($fileReadable);

                    foreach ($fileReadable as $file) {
                        $filePath = str_replace('\\', '/', $file);
                        $fileSum = md5_file($filePath);

                        if (in_array($fileSum, $whitelistMD5Sums)) { // if in whitelist skip
                            continue;
                        } elseif (in_array($fileSum, $blacklistMD5Sums)) { // if in blacklist alert and remove
                            echo sprintf('<tr><td><span style="color:red;">%s (Blacklist)</span></td></tr>', $filePath);
                            unlink($filePath);
                            continue;
                        } // else check the token

                        $vTotalRes = @vTotalCheckHash($fileSum);

                        if (isset($vTotalRes['data'])) {
                            if ($vTotalRes['data']['attributes']['total_votes']['malicious'] > 0) {
                                echo sprintf('<tr><td><span style="color:red;">%s (VTotal Malicious)</span></td></tr>', $filePath);
                                continue;
                            } else if (!empty(inStringArray('webshells', $vTotalRes))) {
                                echo sprintf('<tr><td><span style="color:red;">%s (VTotal Webshell)</span></td></tr>', $filePath);
                                continue;
                            }
                        }

                        $tokens = getFileTokens($filePath);
                        $cmp = compareTokens($tokenNeedles, $tokens);
                        $cmp = implode(', ', $cmp);

                        if (!empty($cmp)) {
                            echo sprintf('<tr><td><span style="color:orange;">%s (%s)</span></td></tr>', $filePath, $cmp);
                        }
                    }
                }
                ?>
            </table>
        </form>
    </body>

</html>