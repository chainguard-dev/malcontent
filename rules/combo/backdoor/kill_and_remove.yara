rule kill_and_remove : notable {
  meta:
    hash_2021_malxmr = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2022_CloudMensis_mdworker3 = "273633eee4776aef40904124ed1722a0793e6567f3009cdb037ed0a9d79c1b0b"
    hash_2011_bin_fxagent = "737bb6fe9a7ad5adcd22c8c9e140166544fa0c573fe5034dfccc0dc237555c83"
    hash_2017_AptorDoc_Dok_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2021_Tsunami_gjirtfg = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2021_Tsunami_Kaiten_ujrzc = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
  strings:
    $rm_f = "rm -f"
    $rm_Rf = "rm -Rf"
    $rm_rf = "rm -rf"
    $k_killall = "killall"
    $k_pgrep = "pgrep"
    $k_pkill = "pkill"
    $not_shell_help = "$progname: "
    $not_tempdir = "rm -rf \"$TEMPDIR\""
  condition:
    1 of ($rm*) and 1 of ($k*) and none of ($not*)
}
