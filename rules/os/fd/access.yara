rule bsd_streams: harmless bsd {
  meta:
    description = "Access file descriptors"
    pledge      = "stdio"
    ref         = "https://man7.org/linux/man-pages/man2/access.2.html"

  strings:
    $_fclose  = "_fclose"
    $_fflush  = "_fflush"
    $_fopen   = "_fopen"
    $_rewind  = "_rewind"
    $_fgetpos = "_fgetpos"
    $_fsetpos = "_fsetposs"
    $_ftell   = "_ftell" fullword
    $_ftello  = "_ftello" fullword
    $fdopen   = "fdopen" fullword
    $freopen  = "freopen" fullword
    $fmemopen = "fmemopen" fullword
    $setbuf   = "_setbuf" fullword

  condition:
    any of them
}

rule _close: harmless {
  strings:
    $_close = "_close"

  condition:
    any of them
}
