rule random_uuid: medium {
  meta:
    description = "generates a random UUID"

  strings:
    $ref = "randomUUID"

  condition:
    any of them
}
