rule unlink: posix {
  meta:
    pledge      = "wpath"
    syscall     = "unlink"
    description = "deletes files"
    ref         = "https://man7.org/linux/man-pages/man2/unlink.2.html"

  strings:
    $unlink   = "unlink" fullword
    $unlinkat = "unlinkat" fullword
    $py       = /os.remove\([\w\.\(\), ]{0,64}/
    $objc     = "deleteFile" fullword

  condition:
    any of them
}

rule rm_f_hardcoded_tmp_path: medium posix {
  meta:
    ref = "https://attack.mitre.org/techniques/T1485/"

  strings:
    $ref     = /rm +\-[a-zA-Z]{,1}f[a-zA-Z]{,1} \/(tmp|var|dev)\/[\w\/\.\-\%]{0,64}/
    $not_apt = "/var/lib/apt/lists"

  condition:
    $ref and none of ($not*)
}

rule del: medium windows {
  meta:
    description = "deletes files"

  strings:
    $del            = "del "
    $cmd_echo       = "echo off"
    $cmd_powershell = "powershell"

  condition:
    filesize < 16KB and $del and any of ($cmd*)
}

rule DeleteFile: medium {
  meta:
    description = "delete a file"

  strings:
    $create = /DeleteFile\w{0,8}/

  condition:
    any of them
}

rule delete_files_in_dir: medium {
  meta:
    description = "deletes files in a directory"

  strings:
    $remove  = /os.remove\([\w\.\(\), ]{0,64}/
    $listdir = /os.listdir\([\w\.\(\), ]{0,64}/

  condition:
    all of them and @remove > @listdir and (@remove - @listdir) < 32
}
