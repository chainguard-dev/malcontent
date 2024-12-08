rule random_uuid: medium {
  meta:
    description = "generates a random UUID"

  strings:
    $ref = "randomUUID"

  condition:
    any of them
}

rule uuid: harmless {
  meta:
    description = "generates a random UUID"

  strings:
    $java = "java/util/UUID"

  condition:
    any of them
}
