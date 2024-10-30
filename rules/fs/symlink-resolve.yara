rule realpath {
  meta:
    pledge      = "rpath"
    description = "resolves symbolic links"
    ref         = "https://man7.org/linux/man-pages/man3/realpath.3.html"

  strings:
    $ref = "realpath" fullword

  condition:
    $ref
}
