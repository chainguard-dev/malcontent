rule exfil_whoami_hostname: high {
  meta:
    description = "gathers host data and invokes curl"

  strings:
    $curl     = "curl" fullword
    $hostname = "hostname" fullword
    $whoami   = "whoami" fullword
    $https    = "https://"
    $http     = "http://"

  condition:
    filesize < 8KB and $curl and $hostname and $whoami and any of ($http*)
}
