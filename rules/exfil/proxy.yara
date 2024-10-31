rule ngrok: medium {
  meta:
    ref                                   = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description                           = "References known file hosting site"
    hash_2023_Linux_Malware_Samples_24f3  = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
    hash_2023_Linux_Malware_Samples_4eae  = "4eae9a20919d84e174430f6d33b4520832c9a05b4f111bb15c8443a18868c893"
    hash_2022_calculator_2c397c49ab20c445 = "36d2f1e4e7b344228b954261731b6b1711b2a689df5c03f2dbd6324081e45941"

  strings:
    $d_pastebin = "ngrok.io"

  condition:
    any of ($d_*)
}
