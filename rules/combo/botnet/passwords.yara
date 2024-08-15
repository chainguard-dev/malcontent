
rule router_password_references : critical {
  meta:
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Trojan_Gafgyt_8413 = "84131fcec395843710e3b8daf378e92ce54a12bf190d4d354bb50cf000e557d3"
  strings:
    $f_hikvision = "hikvision"
    $f_cuadmin = "CUAdmin"
    $f_assword = "assword"
    $f_xmhdipc = "xmhdipc"
    $f_admin = "admin"
    $f_root = "root"
    $f_guest = "guest"
    $f_lnadmin = "lnadmin"
    $f_123qwe = "123qwe"
    $f_tsgoingon = "tsgoingon"
    $f_qE6MGAbI = "qE6MGAbI"
    $f_jvbzd = "jvbzd"
    $f_123456 = "123456"
    $f_qwerty = "qwerty"
    $f_root123 = "root123"
    $f_passw0rd = "Passw0rd"
    $f_admin123 = "admin123"
    $f_Admin123 = "Admin123"
    $not_onepassword_sdk = "github.com/1password/onepassword-sdk"
  condition:
    8 of ($f*) and none of ($not*)
}
