rule file_write {
  meta:
    description = "writes to file"

  strings:
    $ref  = /[\w\:]{0,16}write[\w\:]{0,8}File[\w\:]{0,32}/
    $ref2 = "WriteFile"
    $ref3 = "writeFile"

  condition:
    any of them
}

rule python_file_write {
  meta:
    description = "writes to a file"
    filetypes   = "py"

  strings:
    $val = /open\([\"\'\w\.]{1,32}\, {0,2}["'][wa]["']\)/
    $x   = "file.write("

  condition:
    filesize < 1MB and any of them
}

rule ruby_file_write: medium {
  meta:
    description = "writes to a file"
    filetypes   = "rb"

  strings:
    $val = /File\.open\(.{1,64} {0,2}["']w[ab\+]{0,2}["']\)/

  condition:
    filesize < 1MB and any of them
}

rule powershell_fs_write {
  meta:
    description = "writes content to disk"
    syscall     = "pwrite"
    filetypes   = "ps1"

  strings:
    $write_val = "System.IO.File]::WriteAllBytes"

  condition:
    any of them
}
