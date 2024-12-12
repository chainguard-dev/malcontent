rule minecraft: medium {
  meta:
    description = "Has references to Minecraft"

  strings:
    $val1 = "minecraft"
    $val2 = "Minecraft"
    $val3 = "MINECRAFT"

  condition:
    any of them
}

rule hidden_minecraft: medium {
  meta:
    description = "accesses minecraft configuration data"

  strings:
    $val1 = ".minecraft" fullword

  condition:
    any of them
}

rule essential_microsoft_accounts: high {
  meta:
    description = "accesses Minecraft credentials"

  strings:
    $ = "microsoft_accounts.json"
    $ = "essential"

  condition:
    all of them
}

