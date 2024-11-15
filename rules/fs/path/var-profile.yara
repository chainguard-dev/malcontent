rule var_profile: medium {
  meta:
    description = "references '/var/profile', the default target of LD_PROFILE_OUTPUT"

  strings:
    $ref = "/var/profile" fullword

  condition:
    $ref
}
