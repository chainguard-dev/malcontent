rule sigkill_multiple : notable {
  meta:
    hash_2022_gimmick_coreldraw = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
    hash_2021_malxmr = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2023_Sodinokibi = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2022_CloudMensis_mdworker3 = "273633eee4776aef40904124ed1722a0793e6567f3009cdb037ed0a9d79c1b0b"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2021_Tsunami_gjirtfg = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
  strings:
    $s_xargs_kill_9 = "xargs kill -9"
    $s_kill_9_backtick = "kill -9 `"
    $s_pkill_9 = "pkill -9"
    $s_kill_9_subshell = "kill -9 $("
    $s_killall_9 = "killall -9"
    $s_xargs_I_kill = /xargs -I \w{1,64} kill/
    $s_xargs_I_docker_kill = /xargs -I \w{1,64} docker kill/
    $not_official = "All Rights Reserved"
    $not_sysdiagnose = "PROGRAM:sysdiagnose"
	$not_postfix = "Postfix"
  condition:
    any of ($s*) and none of ($not*)
}
