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
    $token = token_get_all($fileContent);

    // Create an output array
    $output = array();

    // Iterate over the tokens and add the token types to the output array
    foreach ($token as $item) {
        if (isset($item[1])) {
            $output[] = strtolower($item[1]);
        }
    }

    // Remove any duplicate or empty tokens from the output array
    $output = array_values(array_unique(array_filter(array_map("trim", $output))));

    // Return the output array
    return $output;
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
        if (in_array($tokenNeedle, $tokenHaystack)) {
            $output[] = $tokenNeedle;
        }
    }
    return $output;
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

$blacklistMD5Sums = array(
    'da18ee332089bc79e5906d254e05da85', // adminer
    'd68181147fd360e501a8c47a8f11db12',
    'cde87e013ff1042438a61eba13a8b84f',
    '984a207fe749cf6c3ae5def462b25cb8',
    '5ecdefd3914452f29dc01b53af1dae62',
    '52282a4579f6c97c0ea26b153bbaedfc',
    '0e631fea018d9acbea134a89fb89ed9d',
    '9cef8472ff468b3c36ae04cdc2ff5e57',
    '23f5c862d6b537bbd220cab81cfde3e9',
    '810bcc06123b712c67120c00bc1f97ea',
    '11b4c780f460b91be40d1bf831c8dabd',
    'e5327e50ab0e5805a91ca4bb844178df',
    '06fe42819e916f85df5e330c168f43dc',
    '37e729fadce14aab41ad45c4b9adb76e',
    '7c58272b434fd8ffda14ce21a9df34b5',
    'a2b5342a539fb9d65f90a4c501160774',
    'ab767da87df14fe0850717c02848d190',
    '445e63fa6adf1de27cae31aefca7e1d0',
    '4753c4379a6f7204e343ad83d3ffebcf',
    '261b87beaa63e785d94a002630184c1e',
    '4de688d75d5659c57a193a1bdbd5ab14',
    '9cef8472ff468b3c36ae04cdc2ff5e57', //jfu
    '6ebc6f001db13eb0ba353c8dae2d2de4',
    'b43c94ea8e371f08cec65f78b9b7cc3d',
    'd36a7ca98675a5efb2f21987b7d82bf7',
    'f8518441192a31c0461a79233c19c0d1',
    '77dbc95f089574059ea71fbec588060d',
    '179af89c89370dcc3d6c8832eb394042',
    '331a7e445ae852339a4af0f5ac2866a4',
    'f42aea7b83c9532d2673d9712b41d785',
    'cd60beff30290e59e9e172af1ea2b13f',
    '5446efdda3ce337b27081bd38ef00ff6',
    'f042a553164e4ffdcf7025f90a9b7559',
    'd01d7f10beba62cc4b189a4973688308',
    'ac45d5d0ed24e176dab7acf222135728',
    'a763898649dd69c7e5920dd77d480753',
    'e057c74e8c7910886538d6e55d0b16e6',
    'e68cd7c45133c0c7b4ecbb7218677b00',
    'd148e3338a5bd87d7ed0f695d92b9dd1',
    '2dab5576695298f017741b114f67c3f1',
    '9a5f5586560f3c05a13ec0006bb3e76d',
    '6b2f5cad2a9fbe03d76be0cee82ef282',
    'd93f7529cc0b89631a55c1fecb3c98c0',
    'acd20b834347718afedebfbd6b46fbf2',
    '999ed45a021e280f3d6ccaa9d47cbe92',
    '881b2214024eb58bd8623fdad8044964',
    'b5c698c1944b6ee0187ea95a104b2a14',
    'c897d3bd4820bc96c72617d4102446d8',
    '96224fe86d2d20812147d400b559e632',
    'dd86d0bc2255302f7f32f3c04f03d24c',
    '6cc76080a7503fbe70812e6d793b885e',
    '0bacb1196e4a8ea56b244b6dcb4999d0',
    'e5ab6267248c146c6baed601050e7f1a',
    '11f1a6317420a0f4c1bdd94e66e94ca3',
    'b83ffbfceb357ba882e4fb99ce16321f',
    '521acf9fd3a5409fea57789b14d62105',
    '6b5bd3739b8613dde9542d18e7dc49b7',
);


$content = file_get_contents('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/whitelist.txt');
$whitelistMD5Sums = explode("\n", $content);
//$content = file_get_contents('https://raw.githubusercontent.com/Cvar1984/sussyfinder/main/blacklist.txt');
//$blacklistMD5Sums = explode("\n", $content);
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
        function copytable(el) {var urlField = document.getElementById(el)
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

                    $tokens = getFileTokens($filePath);
                    $cmp = compareTokens($tokenNeedles, $tokens);
                    $cmp = implode(', ', $cmp);

                    if (!empty($cmp)) {
                        echo sprintf('<tr><td><span style="color:orange;">%s (%s)</span></td></tr>', $filePath, $cmp);
                    }
                }
            }