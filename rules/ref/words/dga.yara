rule dga_url : higb {
  meta:
    description = "References Domain Generation Algorithm for C2 discovery"
  strings:
    $ = "dgaURL" fullword
    $ = "dgaUrl" fullword
    $ = "dgaurl" fullword
  condition:
    any of them
}
