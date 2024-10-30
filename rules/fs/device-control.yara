rule ioctl: harmless {
  meta:
    pledge      = "wpath"
    syscall     = "ioctl"
    description = "manipulate the device parameters of special files"

  strings:
    $ioctl = "ioctl" fullword

  condition:
    any of them
}
