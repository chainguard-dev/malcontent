rule ukraine: medium {
  meta:
    description = "Glory to Ukraine!"

  strings:
    $ref = "слава Украине!"

  condition:
    any of them
}
