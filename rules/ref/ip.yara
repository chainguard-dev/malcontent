rule hardcoded_ip : suspicious {
  meta:
    hash_2023_XorDDoS = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2023_stealer_hashbreaker = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_amos_stealer_e = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_trojan_Mirai_ubzhp = "98e7808bd5bfd72c08429ffe0ffb52ae54bce7e6389f17ae523e8ae0099489ab"
    hash_2021_malxmr = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2023_trojan_Gafgyt_Mirai_gnhow = "b56a89db553d4d927f661f6ff268cd94bdcfe341fd75ba4e7c464946416ac309"
    hash_2023_trojan_Mirai_ghwow = "c91c6dbfa746e3c49a6c93f92b4d6c925668e620d4effc5b2bf59cf9100fe87d"
    hash_2018_MacOS_conx = "5a8aa3e5ae430a7e466b80875375cb7196a9cfa21964f373a6941426f24ea55e"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2018_Contents_document = "7b90fe8aec599625dd7d4ce0026f839c16fc12aa11839a88055cf49a6db9529b"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2021_trojan_Gafgyt_5E = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
    hash_2020_Rekoobe_egiol = "6fc03c92dee363dd88e50e89062dd8a22fe88998aff7de723594ec916c348d0a"
    hash_2021_trojan_Gafgyt_23DZ = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
    hash_2021_trojan_Mirai_hefhz = "f01a3c987b422cb86b05c7e65338b238c4b7da5ce13b2e5fcc38dbc818d9b993"
  strings:
    $ipv4 = /([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/
    $ipv4_hostport = /([0-9]{1,3}\.){3}[0-9]{1,3}:\d{2,5}/
    $not_localhost = "127.0.0.1"
    $not_broadcast = "255.255.255.255"
    $not_upnp = "239.255.255.250"
    $not_weirdo = "635.100.12.38"
    $not_incr = "10.11.12.13"
    $not_169 = "169.254.169.254"
  condition:
    1 of ($ip*) and none of ($not*)
}

rule http_hardcoded_ip : suspicious {
  strings:
    $ipv4 = /https*\/\/([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/
  condition:
    any of them
}
