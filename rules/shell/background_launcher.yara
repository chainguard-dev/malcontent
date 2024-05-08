
rule hidden_background_launcher : suspicious {
  meta:
    description = "Launches background processes from a hidden path"
    hash_2023_rc_d = "30b0e00414ce76f7f64175fb133632d5c517394bc013b0efe3d8ead384d5e464"
  strings:
    $b_hidden_background = /\/\.[\w\/ \.\%]{1,64} \&[^&]/
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_from = "from &"
  condition:
    any of ($b*) and none of ($not*)
}

rule relative_background_launcher : suspicious {
  meta:
    description = "Launches background processes from a relative path"
    hash_2023_src_pscan = "59bb224cca5d33e442d21da26a33eaab1aa57dac5ba4e43bd72e262d115c23c8"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
  strings:
    $b_relative_background = /\.\/\w[\w\/ \.\%]{1,64} \&[^&]/
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_from = "from &"
  condition:
    any of ($b*) and none of ($not*)
}
