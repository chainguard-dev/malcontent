include "rules/global.yara"

rule app_path: medium {
  meta:
    description = "references hardcoded application path"

  strings:
    $ref = /\/Applications\/.{0,32}\.app\/Contents\/MacOS\/[\w \.\-]{0,32}/

  condition:
    any of them
}

rule macho_app_path: high {
  meta:
    description = "references hardcoded application path"
    filetypes   = "macho"

  strings:
    $ref = /\/Applications\/.{0,32}\.app\/Contents\/MacOS\/[\w \.\-]{0,32}/

  condition:
    specific_macho and any of them
}

rule mac_applications: medium {
  meta:
    description = "references /Applications directly"
    filetypes   = "macho"

  strings:
    $ref = "/Applications" fullword

  condition:
    specific_macho and any of them
}
