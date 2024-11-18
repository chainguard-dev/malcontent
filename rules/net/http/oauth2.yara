rule oauth2 {
  meta:
    description = "supports OAuth2"

  strings:
    $ref  = "oauth2" fullword
    $ref2 = "OAuth 2"

  condition:
    any of them
}
