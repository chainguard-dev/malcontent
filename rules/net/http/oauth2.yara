rule oauth2 {
  meta:
    description = "supports OAuth2"

  strings:
    $ref  = "oauth2" fullword
    $ref2 = "OAuth 2"

  condition:
    any of them
}

rule token {
  meta:
    description = "supports OAuth2"

  strings:
    $ref  = "clientId"
    $ref2 = "refreshTok"
    $ref3 = "clientSecr"

  condition:
    all of them
}
