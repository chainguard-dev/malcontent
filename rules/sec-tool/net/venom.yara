rule venom: critical {
  meta:
    description = "Uses Venom, a multi-hop proxy and RAT for penetration testers"

  strings:
    $ref1 = "/Venom/agent"
    $ref2 = "venom_agent"
    $ref3 = "Dliv3/Venom"

  condition:
    any of them
}
