rule etc_ssl_private: medium {
  meta:
    description = "access SSL private key material"

  strings:
    $ref = "/etc/ssl/private"

  condition:
    any of them
}
