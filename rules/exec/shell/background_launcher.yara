rule hidden_background_launcher: high {
  meta:
    description    = "Launches background processes from a hidden path"
    hash_2023_rc_d = "30b0e00414ce76f7f64175fb133632d5c517394bc013b0efe3d8ead384d5e464"

  strings:
    $b_hidden_background = /\/\.[\w\/ \.\%]{1,64} \&[^&]/
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_node            = "NODE_DEBUG_NATIVE"
    $not_from            = "from &"

  condition:
    any of ($b*) and none of ($not*)
}

rule relative_background_launcher: high {
  meta:
    description         = "Launches background processes from a relative path"
    hash_2023_src_pscan = "59bb224cca5d33e442d21da26a33eaab1aa57dac5ba4e43bd72e262d115c23c8"

    hash_2011_bin_fxagent = "737bb6fe9a7ad5adcd22c8c9e140166544fa0c573fe5034dfccc0dc237555c83"

  strings:
    $b_relative_background = /\.\/\w[\w\/ \.\%]{1,64} \&[^&]/
    $not_private           = "/System/Library/PrivateFrameworks/"
    $not_node              = "NODE_DEBUG_NATIVE"
    $not_from              = "from &"

  condition:
    any of ($b*) and none of ($not*)
}
