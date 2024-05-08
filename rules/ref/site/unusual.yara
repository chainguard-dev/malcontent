
rule unusual_http_hostname : suspicious {
  meta:
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_UPX_cc996d19c3e9b732b5f61fb7a2ad20a4f9e1fd7e62f484f15c7cc984a32dec01_elf_mips = "da7ab6f220f797d3fe3e0daf704cdceba25f3c21f108457344c475de6a23ccf5"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
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
