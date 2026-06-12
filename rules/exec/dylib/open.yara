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

rule java_native_library_load: medium java {
  meta:
    description = "loads a bundled native library from Java"
    filetypes   = "class,jar,java"

  strings:
    $system  = "java/lang/System"
    $load    = "loadLibrary" fullword
    $so_lib  = /lib[\w\-]{2,32}\.so/
    $so_path = /\/[\w\-\.\/]{1,64}\.so/

  condition:
    filesize < 2MB and $system and $load and any of ($so*)
}
