rule minecraft: medium {
  meta:
    description = "Has references to Minecraft"

  strings:
    $val1 = "minecraft" fullword
    $val2 = "Minecraft" fullword
    $val3 = "MINECRAFT" fullword

  condition:
    any of them
}
