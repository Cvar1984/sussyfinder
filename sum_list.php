<?php

function calculateMd5($file) {
  return md5_file($file);
}

function listFilesRecursively($directory) {
  $files = array();
  $iterator = new RecursiveDirectoryIterator($directory);
  foreach (new RecursiveIteratorIterator($iterator) as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
      $files[] = $file->getPathname();
    }
  }
  return $files;
}

$targetDirectory = $argv[1];
$phpFiles = listFilesRecursively($targetDirectory);

foreach ($phpFiles as $file) {
  $md5sum = calculateMd5($file);
  echo "$md5sum\n";
}