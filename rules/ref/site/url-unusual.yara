
rule unusual_nodename {
  meta:
	description = "Contains HTTP hostname with a long node namhe"
  strings:
    $ref = /https*:\/\/\w{16,}\//
  condition:
	$ref
}

rule exotic_tld {
  meta:
    description = "Contains HTTP hostname with unusual top-level domain"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2018_Contents_document = "7b90fe8aec599625dd7d4ce0026f839c16fc12aa11839a88055cf49a6db9529b"
    hash_2021_trojan_Mirai_gnlsp = "bc5c2358e58876be7955fa0c8f5514f4d35e5353b93ba091216b2371470da988"
    hash_2021_trojan_Mirai_Tsunami = "c8aeb927cd1b897a9c31199f33a6df9f297707bed1aa0e66d167270f1fde6ff5"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
  strings:
    $http_exotic_tld = /https*:\/\/[\w\-\.]{1,128}\.(vip|red|cc|wtf|top|pw|ke|space|zw|bd|ke|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|online|poker)\//
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_nips = "nips.cc"
    $not_gov_bd = ".gov.bd"
  condition:
    any of ($http*) and none of ($not_*)
}