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
    $ref              = /Content-Length: \d{2,13}/ fullword
    $not_test_parse   = "test_parse"
    $not_slash_test   = "/test" fullword
    $not_test_message = "test_message"
    $not_unit_test    = "unit test"

  condition:
    $ref and none of ($not*)
}
