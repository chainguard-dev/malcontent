
rule dial_shared_screen_discovery : suspicious {
  meta:
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_trojan_Mirai_leeyo = "ff2a39baf61e34f14f9c49c27faed07bdd431605b3c845ab82023c39589e6798"
    hash_2023_Linux_Malware_Samples_341a = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
    hash_2023_Linux_Malware_Samples_cbad = "cbadb658ba16ad9a635cdd984ce56bb3f39da33524aded8d40371c0e1ae9be44"
    hash_2023_Linux_Malware_Samples_dcd3 = "dcd318efe5627e07a8eda9104ede1f510e43f5c0ae7f74d411137e1174f2844b"
    hash_2023_Linux_Malware_Samples_fdcd = "fdcda1da780db220c77a44b294221a2ab9f2ca8c60f84d65e032cb5bc271e927"
    hash_2023_UPX_346d49f539e31f1caaa102385742761e4f8fbc8e7e0e9981a018d79cd908c6b2_elf_x86 = "9c33e6aad8862369c6d1e8bc87daa568dc5ff44bc49a109d8bcafdbce626556c"
  strings:
    $urn_multiscreen = "urn:dial-multiscreen-org:service:dial:1"
    $not_chromium = "RasterCHROMIUM"
  condition:
    $urn_multiscreen and none of ($not*)
}
