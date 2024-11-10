rule chflags_hidden: high {
  meta:
    description = "hides files using chflags"
    ref         = "https://man.freebsd.org/cgi/man.cgi?chflags(1)"

  strings:
    $chflags = /chflags.{0,3} hidden [\w\.\/]{0,24}/

  condition:
    any of them
}
