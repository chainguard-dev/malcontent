rule semicolon_relative_path : suspicious {
  meta:
    ref = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_trojan_Mirai_aspze = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
    hash_2021_gjif_tsunami_Gafygt = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
    hash_2021_trojan_Mirai_leeyo = "ff2a39baf61e34f14f9c49c27faed07bdd431605b3c845ab82023c39589e6798"
    hash_2023_Linux_Malware_Samples_cbad = "cbadb658ba16ad9a635cdd984ce56bb3f39da33524aded8d40371c0e1ae9be44"
    hash_2021_trojan_Mirai_gsjmm = "dcd318efe5627e07a8eda9104ede1f510e43f5c0ae7f74d411137e1174f2844b"
    hash_2023_Linux_Malware_Samples_fdcd = "fdcda1da780db220c77a44b294221a2ab9f2ca8c60f84d65e032cb5bc271e927"
  strings:
    $semi_relative = /[\/\w]{3,};[ +]{0,8}\.\/\.{0,8}\w{3,}/
  condition:
    any of them
}
