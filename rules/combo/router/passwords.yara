rule router_password_references : critical {
  meta:
    hash_2021_trojan_Mirai_Gafgyt_bonb = "68c67c4e38c1b5a1a2897c5f6d25456e989f5a94c359137ea040e79ca4a588aa"
    hash_2023_Linux_Malware_Samples_efa8 = "efa875506296d77178884ba8ac68a8b6d6aef24e79025359cf5259669396e8dd"
    hash_2023_Linux_Malware_Samples_efac = "efacd163027d6db6009c7363eb2af62b588258789735352adcbc672cd412c7c1"
    hash_2023_UPX_0c25a05bdddc144fbf1ffa29372481b50ec6464592fdfb7dec95d9e1c6101d0d_elf_x86_64 = "818b80a08418f3bb4628edd4d766e4de138a58f409a89a5fdba527bab8808dd2"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Trojan_Mirai_107e = "107ecf1ab33e6daa7252eb7822fe1b2a720fe33549cd33ff0aa9f9a603aa3d03"
    hash_2023_Unix_Trojan_Mirai_2f98 = "2f987c374944a01717b1905f2bc063a3b577a1d9933a5225717332aa6e43eb90"
    hash_2023_Unix_Trojan_Mirai_3b5f = "3b5fbff58bab53c59d499431e93f753f67dc4836821156191728a05cdabc615e"
  strings:
    $hikvision = "hikvision"
    $cuadmin = "CUAdmin"
    $assword = "assword"
    $xmhdipc = "xmhdipc"
    $admin = "admin"
    $root = "root"
    $guest = "guest"
    $lnadmin = "lnadmin"
    $123qwe = "123qwe"
    $tsgoingon = "tsgoingon"
    $qE6MGAbI = "qE6MGAbI"
    $jvbzd = "jvbzd"
    $123456 = "123456"
    $qwerty = "qwerty"
    $root123 = "root123"
    $passw0rd = "Passw0rd"
    $admin123 = "admin123"
    $Admin123 = "Admin123"
  condition:
    8 of them
}
