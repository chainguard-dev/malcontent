rule built_by_archaic_gcc_version : notable {
  meta:
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2023_icmpshell = "4305c04df40d3ac7966289cc0a81cedbdd4eee2f92324b26fe26f57f57265bca"
    hash_2023_RedAlert_redniev = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2023_Royal = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_blackcat_x64 = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
    hash_2023_HelloKitty_A = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"
    hash_2022_blackbasta_genericac = "96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be"
    hash_2023_trojan_Gafgyt_Mirai_gnhow = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2022_XorDDoS_0Xorddos = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2023_Sodinokibi = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2020_Prometei_B_uselvh323 = "2bc860efee229662a3c55dcf6e50d6142b3eec99c606faa1210f24541cad12f5"
    hash_2020_Prometei_B_uselvh323 = "2bc8694c3eba1c5f066495431bb3c9e4ad0529f53ae7df0d66e6ad97a1df4080"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2021_Tsunami_gjirtfg = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
    hash_2021_CoinMiner_Sysrv = "5f80945354ea8e28fa8191a37d37235ce5c5448bffb336e8db5b01719a69128f"
    hash_2020_Rekoobe_egiol = "6fc03c92dee363dd88e50e89062dd8a22fe88998aff7de723594ec916c348d0a"
    hash_2020_Prometei_lbjon = "75ea0d099494b0397697d5245ea6f2b5bf8f22bb3c3e6d6d81e736ac0dac9fbc"
    hash_2021_trojan_Gafgyt_23DZ = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2021_trojan_Mirai_hefhz = "f01a3c987b422cb86b05c7e65338b238c4b7da5ce13b2e5fcc38dbc818d9b993"
    hash_2021_CoinMiner_Camelot = "fadc69995b9f837837595d73be8dce1bbccf0b709d0d8bb2cadf1c90b46763cf"
  strings:
    $gcc_v4 = /GCC: \([\w \.\-\~]{1,128}\) 4\.\d{1,16}\.\d{1,128}/
    $not_nacl = "NACLVERBOSITY"
  condition:
    $gcc_v4 and none of ($not*)
}
