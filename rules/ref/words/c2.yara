
rule command_and_control : notable {
  meta:
    description = "Uses terms that may reference a command and control server"
    hash_2023_Linux_Malware_Samples_24f3 = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
    hash_2023_Linux_Malware_Samples_444d = "444d8f5a716e89b5944f9d605e490c6845d4af369b024dd751111a6f13bca00d"
    hash_2023_Linux_Malware_Samples_4eae = "4eae9a20919d84e174430f6d33b4520832c9a05b4f111bb15c8443a18868c893"
  strings:
    $c_and_c = "command & control"
    $c2_addr = "c2_addr"
    $c2_port = "c2_port"
    $c2_event = "c2_event"
  condition:
    any of them
}

rule send_to_c2 : suspicious {
  meta:
    description = "References sending data to a C2 server"
  strings:
    $send_to = "SendDataToC2"
  condition:
    any of them
}

rule remote_control : notable {
  meta:
    description = "Uses terms that may reference remote control abilities"
    hash_2023_Linux_Malware_Samples_2c98 = "2c98b196a51f737f29689d16abeea620b0acfa6380bdc8e94a7a927477d81e3a"
    hash_2023_Linux_Malware_Samples_3292 = "329255e33f43e6e9ae5d5efd6f5c5745c35a30d42fb5099beb51a6e40fe9bd76"
    hash_2023_Linux_Malware_Samples_3ffc = "3ffc2327a5dd17978f62c44807e5bf9904bcdef222012a11e48801faf6861a67"
  strings:
    $ref = "remote_control"
    $ref2 = "remote control"
  condition:
    any of them
}
