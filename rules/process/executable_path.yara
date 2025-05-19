rule python_sys_executable: medium {
  meta:
    description = "gets executable associated to this process"
    filetypes   = "py"

  strings:
    $ref = "sys.executable" fullword

  condition:
    any of them
}

rule custom_path: low {
  meta:
    description = "sets a custom PATH"

  strings:
    $path = "PATH"
    $ref1 = /[\/\w:\-]{0,64}\/sbin:\/bin[\/\w:\-]{0,64}/ fullword
    $ref2 = /[\/\w:\-]{0,64}\/bin:\/usr[\/\w:\-]{0,64}/ fullword
    $ref3 = /[\/\w:\-]{0,64}\/usr\/bin:\/sbin[\/\w:\-]{0,64}/ fullword
    $ref4 = /[\/\w:\-]{0,64}\/bin:\/sbin[\/\w:\-]{0,64}/ fullword

  condition:
    filesize < 20MB and $path and any of ($ref*)
}
