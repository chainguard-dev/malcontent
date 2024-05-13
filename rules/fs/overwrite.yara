
rule background_dd : high {
  meta:
    ref = "https://cert.gov.ua/article/6123309"
    hash_2023_uacert_dd_bg = "171288619486905a2fdf581f24a98f4e19ae928bd31a7fc8bd9d035cb2b8368b"
  strings:
    $rm_rf_bg = /dd if=[\/\w\.\-\" \=]{0,64} &[^&]/
  condition:
    filesize < 10485760 and all of them
}
