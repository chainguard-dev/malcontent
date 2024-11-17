rule bsd_rand {
  meta:
    description = "generate random numbers insecurely"
    ref         = "https://man.openbsd.org/rand"

  strings:
    $_rand = "_rand" fullword
    $srand = "srand" fullword

  condition:
    any of them
}

rule insecure_rand {
  meta:
    description = "generate random numbers insecurely"
    ref         = "https://man7.org/linux/man-pages/man3/srand.3.html"

  strings:
    $ref = "rand" fullword

  condition:
    any of them in (1000..3000)
}

