
rule implant : medium {
  meta:
    description = "Implements a reverse proxy"
  strings:
    $ref = "reverseproxy" fullword
    $ref2 = "reverse_proxy" fullword
    $ref3 = "reverseProxy"
  condition:
    any of ($ref*)
}
