rule pid_inspector_val : suspicious {
  meta:
	description = "accesses unusual process information"
    hash_2023_trojan_Mirai_ubzhp = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2023_trojan_Mirai_thiwm = "abf0f87cc7eb6028add2e2bda31ede09709a948e8f7e56390a3f18d1eae58aa6"
    hash_2023_trojan_Mirai_ghwow = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"
    hash_2023_Linux_Malware_Samples_7ef5 = "7ef53aea7f4308b24db56737ae4ef9d188cdf947639bf078306da599990a2784"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Dropper_Mirai_58c5 = "58c54ded0af2fffb8cea743d8ec3538cecfe1afe88d5f7818591fb5d4d2bd4e1"
    hash_2023_Unix_Trojan_Mirai_1233 = "12330634ae5c2ac7da6d8d00f3d680630d596df154f74e03ff37e6942f90639e"
    hash_2023_Unix_Trojan_Mirai_53cc = "53cc849f32a5a4f0eba71f8edfe08863d706828bcc94210af9c6ebe29bd368f2"
  strings:
    $proc_exe = /\/proc\/[\%\@]\w{1,3}\/exe/
    $proc_cmdline = /\/proc\/[\%\@]\w{1,3}\/cmdline/
    $proc_loginuid = /\/proc\/[\%\@]\w{1,3}\/loginuid/
    $proc_comm = /\/proc\/[\%\@]\w{1,3}\/comm/
    $proc_cgroup = /\/proc\/[\%\@]\w{1,3}\/cgroup/
    $proc_auxv = /\/proc\/[\%\@]\w{1,3}\/auxv/
    $proc_uid_map = /\/proc\/[\%\@]\w{1,3}\/uid_map/
    $not_network_manager = "org.freedesktop.NetworkManager"
  condition:
    filesize < 104857600 and 2 of ($proc*) and none of ($not*)
}
