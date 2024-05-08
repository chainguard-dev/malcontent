
rule getuid_root : notable {
  meta:
    description = "checks if uid=0 (root)"
    hash_2023_setuptool_setuptool_setup = "50c9a683bc0aa2fbda3981bfdf0bbd4632094c801b224af60166376e479460ec"
    hash_2024_aaa_bbb_ccc_setuptool_setup = "50c9a683bc0aa2fbda3981bfdf0bbd4632094c801b224af60166376e479460ec"
  strings:
    $python = "os.getuid() == 0"
    $python_w32 = "ctypes.windll.shell32.IsUserAnAdmin() != 0"
  condition:
    any of them
}
