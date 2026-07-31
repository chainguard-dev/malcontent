rule hidden_background_launcher: high {
  meta:
    description = "Launches background processes from a hidden path"

  strings:
    // The character after "&" must be neither a word character nor a space, so the
    // ampersand has to terminate a command. That rules out the C address-of form
    // ("... &var)") and a prose ampersand ("... & (foo)"), which is what the old
    // "from &" exemption was papering over - and that exemption disabled the rule
    // for any file mentioning the phrase at all.
    $b_hidden_background = /\/\.[\w\/ \.\%]{1,128} \&[^&\w ]/ fullword
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_node            = "NODE_DEBUG_NATIVE"

  condition:
    any of ($b*) and none of ($not*)
}

rule relative_background_launcher: high {
  meta:
    description = "Launches background processes from a relative path"

  strings:
    // See hidden_background_launcher for the trailing character class.
    $b_relative_background = /\.\/\w[\w\/ \.\%\-\:]{1,196} \&[^&\w ]/ fullword
    $not_private           = "/System/Library/PrivateFrameworks/"
    $not_node              = "NODE_DEBUG_NATIVE"

  condition:
    any of ($b*) and none of ($not*)
}
