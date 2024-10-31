rule getpass {
  meta:
    description = "prompt for a password within a terminal"

  strings:
    $ref = "getpass" fullword

  condition:
    any of them
}
