rule interceptor: medium {
  meta:
    description              = "References interception"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"

  strings:
    $ref = /intercept[\w\_]{0,64}/ fullword

  condition:
    any of them
}
