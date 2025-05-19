rule pyobfuscate: high {
  meta:
    description = "uses 'pyobfuscate' packer"
    filetypes   = "py"

  strings:
    $def         = "def" fullword
    $pyobfuscate = "pyobfuscate" fullword

  condition:
    filesize < 1MB and all of them
}
