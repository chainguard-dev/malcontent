rule USER {
  meta:
    description = "Looks up the USER name of the current user"
    ref         = "https://man.openbsd.org/login.1#ENVIRONMENT"

  strings:
    $ref     = "USER" fullword
    $envget  = "getenv"
    $env     = "ENV" fullword
    $environ = "environ" fullword

  condition:
    $ref and any of ($e*)
}
