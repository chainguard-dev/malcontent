
rule excessive_bitwise_math : notable {
  meta:
    description = "excessive use of bitwise math"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/
  condition:
    filesize < 128000 and #x > 10
}
