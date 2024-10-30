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
    $ref  = "/sbin:/bin"
    $ref2 = "/bin:/usr/"
    $ref3 = "/usr/bin:/sbin"
    $ref4 = "/bin:/sbin"

  condition:
    $path and any of ($ref*)
}
