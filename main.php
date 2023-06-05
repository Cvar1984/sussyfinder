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

$minute = 15;
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
function recursiveScan($directory, &$entries_array = array())
{
    // link can cause endless loop
    $handle = @opendir($directory);
    if ($handle) {
        while (($entry = readdir($handle)) !== false) {
            if ($entry == '.' || $entry == '..') {
                continue;
            }
            $entry = $directory . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($entry) && is_readable($directory) && !is_link($directory)) {
                $entries_array = recursiveScan($entry, $entries_array);
            } elseif (is_file($entry) && is_readable($entry)) {
                $entries_array['file_writable'][] = $entry;
            } else {
                $entries_array['file_not_writable'][] = $entry;
            }
        }
        closedir($handle);
    }
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
function getSortedByTime($path)
{
    $result = recursiveScan($path);
    $fileWritable = $result['file_writable'];
    $fileNotWritable = isset($result['file_not_writable']) ? !$result['file_not_writable'] : false;
    $fileWritable = sortByLastModified($fileWritable);

    return array(
        'file_writable' => $fileWritable,
        'file_not_writable' => $fileNotWritable
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
    $fileWritable = $result['file_writable'];
    isset($result['file_not_writable']) ? $result['file_not_writable'] : false;

    foreach ($fileWritable as $entry) {
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
        'file_writable' => $sortedWritableFile,
        'file_not_writable' => $sortedNotWritableFile
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
    /*
    token_get_all() This function not support :
    - Old notation :  "<?  ?>" and "<% %>"
    - heredoc syntax
    - nowdoc syntax (since PHP 5.3.0)
    */
    $fileContent = file_get_contents($filename);
    $fileContent = preg_replace('/<\?([^p=\w])/m', '<?php ', $fileContent); // replace old php tags
    $token = token_get_all($fileContent);
    $output = array();
    $tokenCount = count($token);

    if ($token > 0) {
        for ($i = 0; $i < $tokenCount; $i++) {
            if (isset($token[$i][1])) {
                $output[] .= strtolower($token[$i][1]);
            }
        }
    }
    $output = array_values(
        array_unique(array_filter(array_map("trim", $output)))
    );
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
    'phtml',
    'phar',
    'php3',
    'php4',
    'php5',
    'php7',
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
    'chr',
    'strrev',
    'goto',
    'implode',
    'strtr',
    'extract',
    'substr',
    'mb_substr',
    'substr_replace',
    'preg_replace',
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
    // Server Information
    'posix_getuid',
    'posix_geteuid',
    'posix_getegid',
    'posix_getpwuid',
    'posix_getgrgid',
    'getmyuid',
    'getmygid',
    'fileowner',
    'filegroup',
    'get_current_user',
    'pathinfo',
    'getcwd',
    'sys_get_temp_dir',
    'basename',
    // Database
    'mysql_connect',
    'mysqli_connect',
    'mysqli_query',
    'mysql_query',
    // I/O
    'fopen',
    'file_put_contents',
    'file_get_contents',
    'url_get_contents',
    'move_uploaded_file',
    '$_files',
    'copy',
    // Miscellaneous
    'allow_url_fopen',
    'ini_set',
    'session_start',
    'symlink',
    '__halt_compiler',
    '__compiler_halt_offset__',
    'set_time_limit',
    'memory_limit',
    'max_execution_time',
    'error_reporting',
    'create_function',
    'get_magic_quotes_gpc',
    '$auth_pass',
    '$password',
);
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

                $fileWritable = $result['file_writable'];
                $fileNotWritable = $result['file_not_writable'];
                $fileWritable = sortByLastModified($fileWritable);

                foreach ($fileWritable as $file) {
                    $filePath = str_replace('\\', '/', $file);
                    $tokens = getFileTokens($filePath);
                    $cmp = compareTokens($tokenNeedles, $tokens);
                    $cmp = implode(', ', $cmp);

                    if (!empty($cmp)) {
                        echo sprintf('<tr><td><span style="color:red;">%s (%s)</span></td></tr>', $filePath, $cmp);
                        //unlink($filePath);
                    }
                }
            }