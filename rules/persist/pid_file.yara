
rule pid_file : medium {
  meta:
    description = "pid file, likely DIY daemon"
    hash_2023_Downloads_2f13 = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
    hash_2023_Downloads_d920 = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
  strings:
    $ref = /\w{0,16}pidFile{0,16}/
    $ref2 = /\w{0,16}PidFile{0,16}/
    $ref3 = /\w{0,16}pid_file{0,16}/
    $ref4 = /[\/\~][\w\/]{0,32}\.pid/
    $not_klog = "/klog/v2.pid"
  condition:
    any of ($ref*) and none of ($not*)
}
