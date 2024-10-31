
rule infected : medium {
  meta:
    description = "References being 'infected'"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Linux_Malware_Samples_31e8 = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2023_Linux_Malware_Samples_5880 = "5880e4bbc87fbeff3b0550feeab8f965b66c914100a840db02daa7529d259181"
  strings:
    $ref = "infected"
    $ref2 = "INFECTED"
  condition:
    any of them
}

rule infection : medium {
  meta:
    description = "References 'infectio'"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2023_Linux_Malware_Samples_9e35 = "9e35f0a9eef0b597432cb8a7dfbd7ce16f657e7a74c26f7a91d81b998d00b24d"
    hash_2023_Linux_Malware_Samples_a385 = "a385b3b1ed6e0480aa495361ab5b5ed9448f52595b383f897dd0a56e7ab35496"
  strings:
    $ref3 = "infectio"
  condition:
    any of them
}
