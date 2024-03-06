rule linux_critical_system_paths : notable {
  meta:
	description = "accesses multiple critical Linux paths"
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2022_Winnti = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
    hash_2021_miner_malxmr = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2021_miner_XMR_Stak = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2021_trojan_Mirai_hefhz = "f01a3c987b422cb86b05c7e65338b238c4b7da5ce13b2e5fcc38dbc818d9b993"
  strings:
    $p_var_run = "/var/run"
    $p_tmp = "/tmp"
    $p_bin_sh = "/bin/sh"
    $p_usr = "/usr/"
    $p_etc_init_d = "/etc/init.d"
    $p_busybox = "/bin/busybox"
    $p_proc = "/proc/"
    $p_devices = "/devices/"
    $p_sys_class_net = "/sys/class/net"
    $p_sysctl = "sysctl"
    $p_etc = "/etc/"
    $not_osquery = "OSQUERY_WORKER"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_chromium = "RasterCHROMIUM"
    $not_network_manager = "org.freedesktop.NetworkManager"
  condition:
    8 of ($p*) and none of ($not*)
}


rule linux_critical_system_paths2 : suspicious {
  meta:
	description = "accesses multiple critical Linux paths"
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2022_Winnti = "2f1321c6cf0bc3cf955e86692bfc4ba836f5580c8b1469ce35aa250c97f0076e"
    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
    hash_2021_miner_malxmr = "04b5e29283c60fcc255f8d2f289238430a10624e457f12f1bc866454110830a2"
    hash_2021_Mettle = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2021_miner_XMR_Stak = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2021_trojan_Mirai_hefhz = "f01a3c987b422cb86b05c7e65338b238c4b7da5ce13b2e5fcc38dbc818d9b993"
  strings:
    $p_var_run = "/var/run"
    $p_tmp = "/tmp"
    $p_bin_sh = "/bin/sh"
    $p_usr = "/usr/"
    $p_etc_init_d = "/etc/init.d"
    $p_busybox = "/bin/busybox"
    $p_proc = "/proc/"
    $p_devices = "/devices/"
    $p_sys_class_net = "/sys/class/net"
    $p_sysctl = "sysctl"
    $p_etc = "/etc/"
    $not_osquery = "OSQUERY_WORKER"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_chromium = "RasterCHROMIUM"
    $not_network_manager = "org.freedesktop.NetworkManager"
  condition:
    8 of ($p*) and none of ($not*)
}
