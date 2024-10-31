rule SHELL {
  meta:
    description = "path to active shell"
    ref         = "https://man.openbsd.org/login.1#ENVIRONMENT"

  strings:
    $ref = "SHELL" fullword

  condition:
    all of them
}
