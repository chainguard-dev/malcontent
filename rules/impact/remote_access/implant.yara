rule implant: medium {
  meta:
    description = "References an Implant"

    hash_2024_dodo_sec_chaes = "c347d9501f782d13983a6c7228791c96241311fd7677233b443b25fa053c18d6"

  strings:
    $ref            = "implant" fullword
    $ref2           = "IMPLANT" fullword
    $ref3           = "Implant"
    $not_ms_example = "Drive-by Compromise"

  condition:
    any of ($ref*) and none of ($not*)
}
