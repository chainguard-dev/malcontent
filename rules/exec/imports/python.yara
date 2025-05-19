rule has_import: low {
  meta:
    description = "imports python modules"
    filetypes   = "py"

  strings:
    $ref  = /import [a-z0-9A-Z]{2,12}/ fullword
    $ref2 = /from [a-z0-9A-Z\.]{2,48} import [a-z0-9A-Z]{2,24}/ fullword

  condition:
    filesize < 64KB and any of them
}

rule python_code_as_chr_int: critical {
  meta:
    description = "hides additional import as array of integers"
    filetypes   = "py"

  strings:
    $import       = "import" fullword
    $int_no_space = "105,109,112,111,114,116,32"
    $int_space    = "105, 109, 112, 111, 114, 116, 32"

  condition:
    filesize < 1MB and $import and any of ($int*)
}

rule single_line_import: medium {
  meta:
    description = "imports built-in and executes more code on the same line"
    filetypes   = "py"

  strings:
    $ref = /import [a-z0-9]{0,8};/

  condition:
    filesize < 64KB and $ref
}

rule single_line_import_multiple: high {
  meta:
    description = "imports multiple built-ins on the same line"
    filetypes   = "py"

  strings:
    $ref = /import [a-z0-9]{0,8}; {0,2}import [a-z0-9]{0,8}; {0,2}/

  condition:
    filesize < 64KB and any of them
}

rule single_line_import_multiple_comma: medium {
  meta:
    description = "imports multiple comma spearated built-ins"
    filetypes   = "py"

  strings:
    $ref2 = /import \w{2,8},\w{2,8},\w{2,8},[\w,]{0,64}/

  condition:
    filesize < 64KB and any of them
}

rule __import__: medium {
  meta:
    description = "directly imports code using built-in __import__"
    filetypes   = "py"

  strings:
    $import = /__import__\([\'\w\(\[]\)\],]{0,64}/

  condition:
    filesize < 4MB and any of them
}

rule __import__sus: high {
  meta:
    description = "directly imports code using built-in __import__"
    filetypes   = "py"

  strings:
    $sus = /__import__.{0,128}(zlib|fernet|base64|b64decode|exec\()/

  condition:
    filesize < 4MB and all of them
}

rule zipimport: medium {
  meta:
    description = "loads external module using zipimporter"
    filetypes   = "py"

  strings:
    $zipimporter = "zipimporter"
    $load_module = "load_module"

  condition:
    filesize < 4MB and all of them
}

rule zipimport_obfuscated: high {
  meta:
    description = "loads obfuscated enccrypted module using zipimporter"
    filetypes   = "py"

  strings:
    $must_import      = "import" fullword
    $must_zipimporter = "zipimporter"
    $must_load_module = "load_module"
    $decompress       = "decompress"
    $decode           = "decode"
    $decrypt          = "decrypt"

  condition:
    filesize < 4MB and all of ($must*) and any of ($de*)
}
