rule libsec: medium linux {
  meta:
    description = "may pretend to be a fake library"

  strings:
    $sec = /\/lib\/libsec[\w\.]{0,16}/ fullword
    $dsx = /\/lib\/libdsx[\w\.]{0,16}/ fullword

  condition:
    any of them
}

rule libsec_subdir: high linux {
  meta:
    description = "fake security library directory"

  strings:
    $ref = /\/lib\/libsec[\w\.]{0,16}\/[\.\w\-\%\@]{0,16}/ fullword

  condition:
    any of them
}

rule install_to_lib: high linux {
  meta:
    description = "may transfer fake libraries into /lib"

  strings:
    $cp_p = /cp -p [\w\%\/\.]{0,16} \/lib\/\w{0,16}\.so[\.\s]{0,8}/ fullword
    $cp   = /cp [\w\%\/\.]{0,16} \/lib\/\w{0,16}\.so[\.\s]{0,8}/ fullword
    $mv   = /mv [\w\%\/\.]{0,16} \/lib\/\w{0,16}\.so[\.\s]{0,8}/ fullword

  condition:
    any of them
}
