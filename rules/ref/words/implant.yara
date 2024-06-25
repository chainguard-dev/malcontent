
rule implant : high {
  meta:
    description = "References an Implant"
    hash_2024_D3m0n1z3dShell_demonizedshell = "d7c34b9d711260c1cd001ca761f5df37cbe40b492f198b228916b6647b660119"
    hash_2024_static_demonizedshell_static = "b4e65c01ab90442cb5deda26660a3f81bd400c205e12605536483f979023aa15"
  strings:
    $ref = "implant" fullword
    $ref2 = "IMPLANT" fullword
    $ref3 = "Implant"
    $not_ms_example = "Drive-by Compromise"
  condition:
    any of ($ref*) and none of ($not*)
}
