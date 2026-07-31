rule nmap: medium {
  meta:
    description = "nmap (network map) port scanner"

  strings:
    $ref        = "nmap" fullword
    $r_cmd      = /nmap +\-[A-Za-z]/
    $not_please = "please install the nmap package"

  condition:
    // "nmap" fullword occurs inside "please install the nmap package", so that
    // hint used to silence the whole file; an actual nmap command line is never
    // suppressed by it.
    $r_cmd or ($ref and none of ($not*))
}
