
rule embedded_zstd : notable {
  meta:
    description = "Contains compressed content in ZStandard format"
    ref = "https://github.com/facebook/zstd"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
    hash_2024_Downloads_e70e = "e70e96983734ee23e52391aa96d30670b2dcebb0cbca46c8eddb014f450c661f"
    hash_2024_2024_Previewers = "20b986b24d86d9a06746bdb0c25e21a24cb477acb36e7427a8c465c08d51c1e4"
  strings:
    $ref = { 28 B5 2F FD }
  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $ref
}
