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
