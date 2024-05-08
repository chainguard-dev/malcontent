
rule etc_ld_preload : high {
  meta:
    description = "References /etc/ld.so.preload"
    hash_2023_Lightning_fd28 = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_OrBit_f161 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
  strings:
    $ref = "/etc/ld.so.preload"
  condition:
    any of them
}
