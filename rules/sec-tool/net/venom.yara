
rule venom : critical {
  meta:
    description = "Uses Venom, a multi-hop proxy and RAT for penetration testers"
    hash_2024_Downloads_e100 = "e100be934f676c64528b5e8a609c3fb5122b2db43b9aee3b2cf30052799a82da"
  strings:
    $ref1 = "/Venom/agent"
    $ref2 = "venom_agent"
    $ref3 = "Dliv3/Venom"
  condition:
    any of them
}
