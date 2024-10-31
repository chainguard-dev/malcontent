rule var_profile: medium {
  meta:
    description = "references '/var/profile', found on routers or embedded systems"

  strings:
    $ref = "/var/profile" fullword

  condition:
    $ref
}
