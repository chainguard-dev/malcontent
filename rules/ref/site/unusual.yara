rule unusual_http_hostname : suspicious {
  meta:
    hash_2023_amos_stealer_a = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2019_C_unioncryptoupdater = "631ac269925bb72b5ad8f469062309541e1edfec5610a21eecded75a35e65680"
    hash_2020_OSX_CoinMiner_xbppt = "a2909754783bb5c4fd6955bcebc356e9d6eda94f298ed3e66c7e13511275fbc4"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2018_Contents_document = "7b90fe8aec599625dd7d4ce0026f839c16fc12aa11839a88055cf49a6db9529b"
    hash_2021_trojan_Mirai_gnlsp = "bc5c2358e58876be7955fa0c8f5514f4d35e5353b93ba091216b2371470da988"
    hash_2021_trojan_Mirai_Tsunami = "c8aeb927cd1b897a9c31199f33a6df9f297707bed1aa0e66d167270f1fde6ff5"
  strings:
    $http_long_nodename = /https*:\/\/[a-zA-Z0-9]{16,64}\//
    $http_exotic_tld = /https*:\/\/[\w\-\.]+\.(vip|red|cc|wtf|zw|bd|ke|ru|am|sbs|date|pw|quest|cd|bid|xyz|cm|xxx|casino|poker)\//
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_mail_ru = "go.mail.ru"
    $not_rambler = "novarambler.ru"
	$not_localhost_app = "localhostapplication"
  condition:
    any of ($http*) and none of ($not_*)
}
