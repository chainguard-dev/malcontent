rule oauth2 {
  meta:
    description = "supports OAuth2"

  strings:
    $ref = "oauth2" fullword

  condition:
    any of them
}
