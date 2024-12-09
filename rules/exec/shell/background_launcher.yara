rule hidden_background_launcher: high {
  meta:
    description = "Launches background processes from a hidden path"

  strings:
    $b_hidden_background = /\/\.[\w\/ \.\%]{1,128} \&[^&]/ fullword
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_node            = "NODE_DEBUG_NATIVE"
    $not_from            = "from &"

  condition:
    any of ($b*) and none of ($not*)
}

rule relative_background_launcher: high {
  meta:
    description = "Launches background processes from a relative path"

  strings:
    $b_relative_background = /\.\/\w[\w\/ \.\%\-\:]{1,196} \&[^&]/ fullword
    $not_private           = "/System/Library/PrivateFrameworks/"
    $not_node              = "NODE_DEBUG_NATIVE"
    $not_from              = "from &"

  condition:
    any of ($b*) and none of ($not*)
}
