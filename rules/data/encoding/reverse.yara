rule strrev {
  meta:
    description = "reverses strings"

  strings:
    $ref  = "strrev("
    $ref2 = /strrev\(['"].{0,256}['"]\);/

  condition:
    any of them
}
