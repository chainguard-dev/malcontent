rule mkdir {
  meta:
    description = "creates directories"
    pledge      = "wpath"
    ref         = "https://man7.org/linux/man-pages/man2/mkdir.2.html"

  strings:
    $mkdir        = "mkdir" fullword
    $createFolder = "createFolder" fullword
    $py           = "os.makedirs" fullword

  condition:
    any of them
}
