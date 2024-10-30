rule testing_key {
  meta:
    description = "Contains TESTING KEY directive"

  strings:
    $ref = "TESTING KEY-----"

  condition:
    any of them
}

