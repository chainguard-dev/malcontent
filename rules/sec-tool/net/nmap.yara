rule nmap: medium {
  meta:
    description = "nmap (network map) port scanner"

  strings:
    $ref        = "nmap" fullword
    $r_cmd      = /nmap +\-[A-Za-z]/
    $not_please = "please install the nmap package"

  condition:
    // "nmap" fullword occurs inside "please install the nmap package", so that one
    // hint used to silence the whole file. Each hint accounts for exactly one $ref
    // match, so compare counts and fire only on an nmap reference the hint cannot
    // explain; an actual nmap command line is never suppressed by it.
    $r_cmd or #ref > #not_please
}
