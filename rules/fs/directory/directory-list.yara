rule opendir_readdir: harmless {
  meta:
    description = "Uses libc functions to list a directory"
    pledge      = "rpath"

  strings:
    $opendir   = "opendir" fullword
    $readdir   = "readdir" fullword
    $readdir64 = "readdir64" fullword
    $fdopendir = "fdopendir" fullword
    $taildir   = "taildir" fullword
    $seekdir   = "seekdir" fullword
    $rewinddir = "rewinddir" fullword

  condition:
    any of them
}

rule GoReadDir {
  meta:
    description = "Uses Go functions to list a directory"
    pledge      = "rpath"

  strings:
    $OpenDir = ".OpenDir" fullword
    $ReadDir = ".ReadDir" fullword

  condition:
    any of them
}

rule bin_ls {
  meta:
    description = "Uses /bin/ls list a directory"
    pledge      = "rpath"

  strings:
    $ref = "/bin/ls"

  condition:
    any of them
}

rule NodeReadDir {
  meta:
    description = "Uses NodeJS functions to list a directory"
    pledge      = "rpath"
    filetypes   = "application/javascript"

  strings:
    $ref = ".readdirSync("

  condition:
    any of them
}

rule PythonListDir {
  meta:
    description = "lists contents of a directory"
    pledge      = "rpath"
    filetypes   = "text/x-python"

  strings:
    $ref = ".listdir("

  condition:
    any of them
}

rule java_listdir {
  meta:
    description = "lists contents of a directory"
    pledge      = "rpath"
    filetypes   = "application/java-vm,text/x-java"

  strings:
    $listFiles = "listFiles"

  condition:
    any of them
}
