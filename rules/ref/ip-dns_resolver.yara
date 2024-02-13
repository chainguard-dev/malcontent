rule hardcoded_dns_resolver : suspicious {
  meta:
    hash_2020_CoinMiner_nbtoz = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2020_Prometei_B_uselvh323 = "2bc8694c3eba1c5f066495431bb3c9e4ad0529f53ae7df0d66e6ad97a1df4080"
    hash_2021_trojan_Gafgyt_23DZ = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2021_trojan_Gafgyt_DDoS = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2021_trojan_Gafgyt_Mirai_tlduc_bashlite = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Gafgyt_U = "3eb78b49994cf3a546f15a7fbeaf7e8b882ebd223bce149ed70c96aab803521a"
    hash_2021_trojan_Gafgyt_U = "f7de003967a15ebf61e53e75c4d7b7ebf3455dc9609fe91140be1049019d02b9"
    hash_2021_trojan_Mirai_bmjmd = "e6cd28b713bb3da33b37202296f0f7ccbb68c5769b84d1f1d1e505138e9e355d"
    hash_2022_XorDDoS_0Xorddos = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2023_trojan_Gafgyt_Mirai_gnhow = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
  strings:
    $d_google_public = "8.8.8.8"
    $d_opendns = "208.67.222.222"
    $d_114dns = "114.114.114.114"
  condition:
    any of ($d_*)
}
