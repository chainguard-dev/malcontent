rule python_sys_executable: medium {
  meta:
    description = "gets executable associated to this process"

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
    $ref1 = /[\/\w:]{0,16}\/sbin:\/bin[\/\w:]{0,16}/
    $ref2 = /[\/\w:]{0,16}\/bin:\/usr[\/\w:]{0,16}/
    $ref3 = /[\/\w:]{0,16}\/usr\/bin:\/sbin[\/\w:]{0,16}/
    $ref4 = /[\/\w:]{0,16}\/bin:\/sbin[\/\w:]{0,16}/

  condition:
    filesize < 20MB and $path and any of ($ref*)
}
