rule perror: harmless {
  meta:
    description = "generate error message for a system or library function"
    ref         = "https://man7.org/linux/man-pages/man3/perror.3.html"

  strings:
    $ref = "perror" fullword

  condition:
    any of them in (1000..3000)
}
