
rule obfuscated_macho : suspicious {
  meta:
	description = "Obfuscated machO binary (missing refs)"
    hash_2021_XLoader_kIbwf02l = "97d6b194da410db82d9974aec984cff8ac0a6ad59ec72b79d4b2a4672b5aa8aa"
    hash_2023_MacOS_applet = "54db4cc34db4975a60c919cd79bb01f9e0c3e8cf89571fee09c75dfff77a0bcd"
    hash_2017_DevilRobber = "868926dc8773abddb806327b3ca9928e9d76a32abd273ea16ed73f4286260724"
    hash_2020_finspy_logind_helper3 = "6ab836d19bc4b69dfe733beef295809e15ace232be0740bc326f58f9d31d8197"
    hash_2017_MacOS_logind = "1cf36a2d8a2206cb4758dcdbd0274f21e6f437079ea39772e821a32a76271d46"
    hash_2017_FlashBack = "8d56d09650ebc019209a788b2d2be7c7c8b865780eee53856bafceffaf71502c"
    hash_2020_Enigma_applet = "9aa9c8165dd4bbf65e19c891b780f41a5211f7f3ad04352f6ad6aadcaaa0d96f"
    hash_2016_MacRansom = "617f7301fd67e8b5d8ad42d4e94e02cb313fe5ad51770ef93323c6115e52fe98"
  strings:
    $common_the = " the "
    $common_use = " use "
    $common_failed = "Failed to"
    $common_could_not = "Could not"
    $common_unable = "Unable to"
    $common_socket = "socket"
    $common_syntax = "Syntax:"
    $common_main = "main"
    $common_https = "https:"
    $common_loader = "@loader_path"
    $common_description = "description"
    $common_swift_string = "Swift.String"
    $common_swift_get = "swift_get"
    $common_swift = "_swift_"
	$common_java = "java/lang"
  condition:
    filesize < 52428800 and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and none of ($common*)
}