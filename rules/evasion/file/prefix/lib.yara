rule lib_subdir: high linux {
  meta:
    description = "hides paths within a /lib subdirectory"

  strings:
    $ref = /\/lib\/[\w\.]{1,16}\/\.[\w\-\%\@]{1,16}/ fullword

  condition:
    any of them
}

rule hidden_library: high {
  meta:
    description = "hidden path in a Library directory"

  strings:
    $hidden_library = /\/Library\/\.\w{1,128}/
    $not_dotdot     = "/Library/../"
    $not_private    = "/System/Library/PrivateFrameworks/"

  condition:
    $hidden_library and none of ($not*)
}
