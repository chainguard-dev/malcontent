rule mkdir {
  meta:
    description = "creates directories"
    pledge      = "wpath"
    ref         = "https://man7.org/linux/man-pages/man2/mkdir.2.html"

  strings:
    $mkdir        = "mkdir"
    $createFolder = "createFolder" fullword
    $py           = "os.makedirs" fullword
    $win          = /CreateDirectory\w{0,8}/
    $java         = "createDirectories"

  condition:
    any of them
}
