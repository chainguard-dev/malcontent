rule sleep_and_background : notable {
  meta:
    description = "calls sleep and runs shell code in the background"
    hash_gmera_licatrade = "49feb795e6d9bce63ee445e581c4cf4a8297fbf7848b6026538298d708bed172"
    hash_2019_Cointrazer = "138a54a0a1fe717cf0ffd63ef2a27d296456b5338aed8ef301ad0e90b0fe25ae"
    hash_2019_trojan_NukeSped_Lazarus_AppleJeus = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
    hash_2020_OSX_CoinMiner_xbppt_installer = "b1fff5d501e552b535639aedaf4e5c7709b8405a9f063afcff3d6bbccffec725"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2021_Tsunami_Kaiten = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_3668 = "3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6"
    hash_2021_Tsunami_Kaiten_ujrzc = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_nohup = "nohup"
    $s_sleep = "_sleep"
    $cmd_bg = /\/[a-z]{1,128}\/[\w\/\- \.]{0,32} &[^&]/
    $cmd_bg_redir = "2>&1 &"
    $hash_bang = "#!"
    $not_perldyn = "bin/parldyn"
    $not_perlxsi = "perlxsi"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_private = "/Library/Developer/PrivateFrameworks/"
  condition:
    1 of ($s_*) and 1 of ($cmd_*) and not $hash_bang in (0..2) and none of ($not*)
}
