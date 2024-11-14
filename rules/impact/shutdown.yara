rule shutdown_val: medium {
  meta:
    description            = "calls shutdown command"
    hash_2023_init_d_netfs = "d8e9068316cfb0573fd86b4dbb60abb250ccf1bc9fbdc84b88b6452b01cbd8fa"

  strings:
    $ref  = /shutdown -[\w ]{0,16}/
    $ref2 = "shutdown now"

  condition:
    any of them
}
