rule hmac: low {
  meta:
    description = "Uses HMAC (Hash-based Message Authentication Code)"

  strings:
    $ref = "HMAC.init"

  condition:
    any of them
}
