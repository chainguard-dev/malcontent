rule dylib: harmless {
  meta:
    description = "makes use of dynamic libraries"

  strings:
    $dlopen  = "dlopen" fullword
    $dlclose = "dlclose" fullword
    $win     = "LoadLibrary"

  condition:
    any of them
}

rule ruby_dylib: low ruby {
  meta:
    description = "makes use of dynamic libraries"

  strings:
    $dlopen = /\w{0,16}\.dlopen\("[\w\.\"\)]{1,16}/

  condition:
    any of them
}

