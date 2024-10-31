rule bsd_time: harmless {
  strings:
    $_time = "_time" fullword

  condition:
    any of them
}

rule gettimeofday: harmless {
  meta:
    syscall     = "gettimeofday"
    ref         = "https://man7.org/linux/man-pages/man2/gettimeofday.2.html"
    description = "get time"

  strings:
    $ref = "gettimeofday" fullword

  condition:
    any of them
}
