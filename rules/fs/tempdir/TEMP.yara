rule temp {
  strings:
    $ref     = "temp" fullword
    $ref2    = "TEMP" fullword
    $env_get = "os.environ"
    $env_os  = "getenv"

  condition:
    any of ($env*) and any of ($ref*)
}
