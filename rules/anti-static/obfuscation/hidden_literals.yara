rule hidden_literals: medium {
  meta:
    description = "references hidden literals"

  strings:
    $ref = "hidden_literals"

  condition:
    filesize < 10MB and $ref
}
