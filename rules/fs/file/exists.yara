rule path_exists: low {
  meta:
    description = "check if a file exists"

  strings:
    $ref = "path.exists" fullword

  condition:
    any of them
}

rule java_exists: low {
  meta:
    description = "check if a file exists"
    filetypes   = "java"

  strings:
    $ref  = "java/io/File" fullword
    $ref2 = "exists" fullword

  condition:
    all of them
}
