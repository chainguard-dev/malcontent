rule file_copy: medium {
  meta:
    description = "copy files"

  strings:
    $ref = /copyFile/ fullword

  condition:
    any of them
}

rule file_copy_cp: medium {
  meta:
    description = "copy files using cp"

  strings:
    $ref = /cp [-\w ]{0,2}[ \$\w\/\.\-]{0,32}/ fullword

  condition:
    any of them
}

rule file_copy_force: medium {
  meta:
    description = "forcibly copy files using cp -f"

  strings:
    $ref = /cp [-\w ]{0,2}f [ \$\w\/\.\-]{0,32}/ fullword

  condition:
    any of them
}
