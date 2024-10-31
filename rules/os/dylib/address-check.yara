rule dladdr {
  meta:
    ref         = "https://man7.org/linux/man-pages/man3/dladdr.3.html"
    description = "determine if address belongs to a shared library"

  strings:
    $ref  = "dladdr" fullword
    $ref2 = "dladdr" fullword

  condition:
    any of them
}
