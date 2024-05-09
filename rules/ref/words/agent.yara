
rule agent : medium {
  meta:
    description = "references an 'agent'"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_misc_mktmpio = "f6b7984c76d92390f5530daeacf4f77047b176ffb8eaf5c79c74d6dd4d514b2b"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $ref = /[a-zA-Z_]{0,16}agent/ fullword
    $ref2 = /agent[a-zA-Z_]{0,16}/ fullword
    $user_agent = "user-agent"
  condition:
    any of ($ref*) and not $user_agent
}
