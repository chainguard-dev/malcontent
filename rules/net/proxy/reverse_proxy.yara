rule reverse_proxy: medium {
  meta:
    description = "Implements a reverse proxy"

  strings:
    $ref  = "reverseproxy" fullword
    $ref2 = "reverse_proxy" fullword
    $ref3 = "reverseProxy"
    $ref4 = "rev-proxy" fullword

  condition:
    any of ($ref*)
}
