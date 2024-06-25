rule minecraft : medium {
  meta:
    description = "Has references to Minecraft"
    hash_2024_Downloads_7c63 = "7c636f1c9e4d9032d66a58f263b3006788047488e00fc26997b915e9d1f174bf"
    hash_2023_Linux_Malware_Samples_1ea3 = "1ea3dc626b9ccee026502ac8e8a98643c65a055829e8d8b1750b2468254c0ab1"
  strings:
    $val1 = "minecraft" fullword
    $val2 = "Minecraft" fullword
    $val3 = "MINECRAFT" fullword
  condition:
    any of them
}
