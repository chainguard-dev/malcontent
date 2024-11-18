rule http_auth {
  meta:
    description = "makes HTTP requests with basic authentication"

  strings:
    $ref  = "Www-Authenticate"
    $ref2 = "WWW-Authenticate"
    $ref3 = "www-authenticate"

  condition:
    any of them
}

rule bearer_auth {
  meta:
    description = "makes HTTP requests with Bearer authentication"

  strings:
    $ref  = "Authorization" fullword
    $ref2 = "Bearer" fullword
    $ref3 = /[A-Z_]{0,16}TOKEN/

  condition:
    all of them or ($ref and $ref2)
}
