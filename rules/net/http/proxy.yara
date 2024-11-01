rule proxy_auth {
  meta:
    description = "use HTTP proxy that requires authentication"
    ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization"

  strings:
    $ref = "Proxy-Authorization"

  condition:
    any of them
}

rule proxy_pac {
  meta:
    description = "discover proxy address via PAC file"
    ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file"

  strings:
    $ref = "PACFile" fullword

  condition:
    any of them
}

rule http_proxy_env {
  meta:
    description = "discover proxy address via environment"
    ref         = "https://www.ibm.com/docs/en/ste/11.0.0?topic=node-proxy-configuration-using-environment-variables"

  strings:
    $ref  = "HTTP_PROXY"
    $ref2 = "HTTPS_PROXY"

  condition:
    any of them
}
