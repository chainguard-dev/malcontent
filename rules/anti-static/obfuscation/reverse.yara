rule string_reversal: medium {
  meta:
    description = "reverses strings"

  strings:
    $ref = "split(\"\").reverse().join(\"\")"

  condition:
    any of them
}
