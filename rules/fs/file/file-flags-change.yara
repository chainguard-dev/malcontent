rule chflags {
  meta:
    description = "May update file flags using chflags"
    ref         = "https://man.freebsd.org/cgi/man.cgi?chflags(1)"

  strings:
    $chflags = "chflags" fullword

  condition:
    any of them
}
