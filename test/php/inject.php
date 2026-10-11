<?php
// Injection job for `test/run bench`, `matrix` and `train`: the harder test.
// Real backdoors are usually injected into legitimate files, not dropped as
// files of their own, and the surrounding legitimate code dilutes what a
// detector sees. For each "shell<TAB>host<TAB>id" line of $SUSSY_PAIRS this
// builds the shell injected into the host (prepended or appended, as attackers
// do) in memory, runs main.php's real analysis on it, and appends one JSON row
// (path = id) to $SUSSY_STATE/rows. Nothing is written to disk or executed.
// Set by the prelude (test/lib/php.js phpJob): $SUSSY_MAIN, $SUSSY_STATE,
// $SUSSY_PAIRS, $SUSSY_SKIP. Resumable like extract.php: finished ids go to
// $SUSSY_STATE/done, the current one to $SUSSY_STATE/progress.
//
// Must stay PHP 4.3-safe: `test/run matrix` runs it on every PHP version.
define('SUSSY_LIB', true);
include $SUSSY_MAIN;

/**
 * Whether PHP code is still open at the end of $code (so whatever follows it
 * would be read as PHP).
 */
function endsInPhp($code)
{
    $tokens = @token_get_all($code);
    $last = end($tokens);
    return !(is_array($last) && ($last[0] == T_INLINE_HTML || $last[0] == T_CLOSE_TAG));
}

/**
 * $shell injected into $host. "prepend" puts it above the host's code, the
 * usual injected-index.php pattern; "append" puts it after. Either way each
 * part keeps its own PHP tags, so both still parse as they did alone.
 */
function injectShell($shell, $host, $where)
{
    if ($where == 'prepend') {
        return (endsInPhp($shell) ? $shell . "\n?>" : $shell) . $host;
    }
    return (endsInPhp($host) ? $host . "\n?>" : $host) . "\n" . $shell;
}

if (!is_dir($SUSSY_STATE)) {
    mkdir($SUSSY_STATE, 0777);
}
$skip = array();
foreach (array($SUSSY_SKIP, $SUSSY_STATE . '/done') as $list) {
    if (file_exists($list)) {
        foreach (explode("\0", file_get_contents($list)) as $id) {
            $skip[$id] = 1;
        }
    }
}
$rows = fopen($SUSSY_STATE . '/rows', 'a');
$done = fopen($SUSSY_STATE . '/done', 'a');
foreach (explode("\n", file_get_contents($SUSSY_PAIRS)) as $line) {
    $pair = explode("\t", $line);
    if (count($pair) < 3 || isset($skip[$pair[2]])) {
        continue;
    }
    list($shellPath, $hostPath, $id) = $pair;
    $fh = fopen($SUSSY_STATE . '/progress', 'w');
    fwrite($fh, $id);
    fclose($fh);
    $shell = file_get_contents($shellPath);
    $host = file_get_contents($hostPath);
    if (is_string($shell) && is_string($host)) {
        // Which side by the id, so a rerun builds the same files
        $content = injectShell($shell, $host, (crc32($id) & 1) ? 'append' : 'prepend');
        $fields = analyzeContent($content, $tokenNeedles, true);
        $fields['size'] = strlen($content);
        $fields['md5'] = md5($content);
        $fields['mtime'] = 0;
        $fields['ctime'] = 0;
        $fields['owner'] = 0;
        $fields['is_unreadable'] = false;
        fwrite($rows, jsonEncode(featureRow($id, $fields)) . "\n");
    }
    fwrite($done, $id . "\0");
    fflush($rows);
    fflush($done);
}
echo jsonEncode(array('php' => PHP_VERSION));
