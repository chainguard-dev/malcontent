rule crypto_fernet: medium {
  meta:
    description = "Supports Fernet (symmetric encryption)"

    hash_2024_3web_1_0_0_setup = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"

  strings:
    $ref  = "fernet" fullword
    $ref2 = "Fernet" fullword

  condition:
    any of them
}
