rule content_length_0: medium {
  meta:
    description = "Sets HTTP content length to zero"

  strings:
    $ref = "Content-Length: 0"

  condition:
    $ref
}

rule content_length_hardcoded: high {
  meta:
    description = "Sets HTTP content length to hard-coded value"

  strings:
    $ref = /Content-Length: \d{2,13}/ fullword

  condition:
    $ref
}
