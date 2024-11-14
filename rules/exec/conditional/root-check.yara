rule getuid_root: medium {
  meta:
    description = "checks if uid=0 (root)"

  strings:
    $python     = "os.getuid() == 0"
    $python_w32 = "ctypes.windll.shell32.IsUserAnAdmin() != 0"

  condition:
    any of them
}
