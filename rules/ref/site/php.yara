
rule http_url_with_php : suspicious {
  meta:
    hash_2016_Calisto = "81c127c3cceaf44df10bb3ceb20ce1774f6a9ead0db4bd991abf39db828661cc"
    hash_2020_trojan_webshell_quwmldl_rfxn = "f1375cf097b3f28247762147f8ee3755e0ce26e24fbf8a785fe4e5b42c1fed05"
    hash_2019_trojan_NukeSped_Lazarus_AppleJeus = "e352d6ea4da596abfdf51f617584611fc9321d5a6d1c22aff243aecdef8e7e55"
    hash_2019_Cointrazer = "138a54a0a1fe717cf0ffd63ef2a27d296456b5338aed8ef301ad0e90b0fe25ae"
    hash_2021_Gmera_Licatrade = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2020_Prometei_B_uselvh323 = "2bc8694c3eba1c5f066495431bb3c9e4ad0529f53ae7df0d66e6ad97a1df4080"
    hash_2021_trojan_Gafgyt_U = "3eb78b49994cf3a546f15a7fbeaf7e8b882ebd223bce149ed70c96aab803521a"
    hash_2021_trojan_Mirai_gsjmm = "dcd318efe5627e07a8eda9104ede1f510e43f5c0ae7f74d411137e1174f2844b"
    hash_2020_trojan_SAgnt_vnqci_sshd = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
    hash_2021_trojan_Mirai_bmjmd = "e6cd28b713bb3da33b37202296f0f7ccbb68c5769b84d1f1d1e505138e9e355d"
    hash_2021_trojan_Gafgyt_U = "f7de003967a15ebf61e53e75c4d7b7ebf3455dc9609fe91140be1049019d02b9"
  strings:
    $php_url = /https*:\/\/[\w\.]+\/[\/\w+]\.php/
    $php_question = /[\.\w\-\/:]+\.php\?/
    $php_c = /https*:\/\/%s\/\w+.php/
    $not_bom = "BOMStorage"
    $not_path_example = " <path"
    $not_multi_path_example = "[<path"
    $not_osquery = "OSQUERY_WORKER"
    $not_brotli = "cardshillsteamsPhototruthclean"
    $not_brotli2 = "examplepersonallyindex"
    $not_manual = "manually upload"
  condition:
    any of ($php*) and none of ($not_*)
}
