rule agent: medium {
  meta:
    description = "references an 'agent'"

  strings:
    $ref        = /[a-zA-Z_]{0,16}agent/ fullword
    $ref2       = /agent[a-zA-Z_]{0,16}/ fullword
    $user_agent = "user-agent"

  condition:
    any of ($ref*) and not $user_agent
}
