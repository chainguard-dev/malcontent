rule dlsym: medium {
  meta:
    ref         = "https://man7.org/linux/man-pages/man3/dlsym.3.html"
    description = "get the address of a symbol"

  strings:
    $ref  = "dlsym" fullword
    $ref2 = "dlvsym" fullword

  condition:
    any of them
}
