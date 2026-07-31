rule dev_path: medium {
  meta:
    description = "path reference within /dev"

  strings:
    // $path deliberately carries no left boundary. Requiring the preceding byte to
    // be a non-word byte would reject a relative directory named dev (the
    // "scripts/dev/bless_tests.php" spelling), but it also rejects genuine device
    // paths whose preceding byte happens to be a word character, which is common
    // where string tables are packed without separators. Measured over the sample
    // corpus that boundary drops four references this rule reports today, one of
    // them on a malware sample, and forgoes a fifth on another. Tightening $path is
    // a separate question from the counting fix below and needs its own review of
    // what it removes; see audit.md.
    $path        = /\/dev\/[\w\.\-\/]{1,16}/
    $ignore_null = "/dev/null"
    $ignore_shm  = "/dev/shm/"

  condition:
    // $path matches "/dev/null" and "/dev/shm/" themselves, and nearly every binary
    // mentions /dev/null, so naming them switched the rule off almost everywhere.
    // Counting instead requires a /dev reference the two accepted paths do not
    // account for. Each accepted path begins exactly one $path match and the two can
    // never start at the same offset, so the comparison is exact.
    #path > #ignore_null + #ignore_shm
}
