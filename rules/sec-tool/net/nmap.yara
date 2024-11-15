rule nmap: medium {
  meta:
    description = "nmap (network map) port scanner"

  strings:
    $ref        = "nmap" fullword
    $not_please = "please install the nmap package"

  condition:
    $ref and none of ($not*)
}
