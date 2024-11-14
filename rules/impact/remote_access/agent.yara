rule agent: medium {
  meta:
    description = "references an 'agent'"

    hash_2023_misc_mktmpio = "f6b7984c76d92390f5530daeacf4f77047b176ffb8eaf5c79c74d6dd4d514b2b"

  strings:
    $ref        = /[a-zA-Z_]{0,16}agent/ fullword
    $ref2       = /agent[a-zA-Z_]{0,16}/ fullword
    $user_agent = "user-agent"

  condition:
    any of ($ref*) and not $user_agent
}
