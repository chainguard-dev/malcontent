
rule crypto_fernet : medium {
  meta:
    description = "Supports Fernet (symmetric encryption)"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
    hash_2024_3web_1_0_0_setup = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"
    hash_2024_3web_py_1_0_0_setup = "fd74f0eecebb47178ef98ac9a744daaf982a16287c78fd9cb2fe9713f542f8c5"
  strings:
    $ref = "fernet" fullword
    $ref2 = "Fernet" fullword
  condition:
    any of them
}
