rule gzip {
  meta:
    description = "works with gzip files"
    ref         = "https://www.gnu.org/software/gzip/"

  strings:
    $ref = "gzip" fullword

  condition:
    any of them
}
