rule strrev_multiple: medium {
  meta:
    description = "reverses strings an excessive number of times"

  strings:
    $ref  = "strrev("
    $ref2 = /strrev\(['"].{0,256}['"]\)/

  condition:
    filesize < 64KB and (#ref > 5) or (#ref2 > 5)
}

rule strrev_short: medium {
  meta:
    description = "reverses a short string"

  strings:
    $ref = /strrev\(['"][\w\=]{0,4}['"]\)/

  condition:
    filesize < 64KB and $ref
}

rule strrev_short_multiple: high {
  meta:
    description = "reverses multiple short strings"

  strings:
    $ref = /strrev\(['"][\w\=]{0,4}['"]\)/

  condition:
    filesize < 64KB and #ref > 3
}
