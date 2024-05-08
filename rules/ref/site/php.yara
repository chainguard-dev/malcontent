
rule http_url_with_php : notable {
  meta:
    description = "accesses hardcoded PHP endpoint"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2022_laysound_4_5_2_setup = "4465bbf91efedb996c80c773494295ae3bff27c0fff139c6aefdb9efbdf7d078"
    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
  strings:
    $php_url = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-\?\@=]{0,160}\.php/
    $php_question = /[\.\w\-\_\/:]{0,160}\.php\?[\w\-@\=]{0,32}/
    $php_c = /https*:\/\/%s\/[\w\/\-\_]{0,160}.php/
    $not_bom = "BOMStorage"
    $not_path_example = " <path"
    $not_multi_path_example = "[<path"
    $not_osquery = "OSQUERY_WORKER"
    $not_brotli = "cardshillsteamsPhototruthclean"
    $not_brotli2 = "examplepersonallyindex"
    $not_manual = "manually upload"
    $not_ecma = "http://wiki.ecmascript.org"
  condition:
    any of ($php*) and none of ($not_*)
}
