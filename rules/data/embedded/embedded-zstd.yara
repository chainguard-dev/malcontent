rule embedded_zstd: medium {
  meta:
    description = "Contains compressed content in ZStandard format"
    ref         = "https://github.com/facebook/zstd"

  strings:
    $ref = { 28 B5 2F FD }

  condition:
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and $ref
}
