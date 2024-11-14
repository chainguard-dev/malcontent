rule nmap: medium {
  meta:

  strings:
    $ref        = "nmap" fullword
    $not_please = "please install the nmap package"

  condition:
    $ref and none of ($not*)
}
