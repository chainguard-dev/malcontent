
rule impossibly_small_elf_program {
  meta:
    hash_2022_GetShell_ConnectBack = "cd54a34dbd7d345a7fd7fd8744feb5c956825317e9225edb002c3258683947f1"
    hash_2021_trojan_Dakkatoni_hafbful = "16e09592a9e85cd67530ec365ac2c50e48e873335c1ad0f984e3daaefc8a57b5"
    hash_2021_trojan_Hack_msfencode = "4c33e1ec01b8ad98f670ba6ec6792d23d1b5d3c399990f39ffd7299ac7c0646f"
    hash_2021_trojan_Linux_Agent_Rare = "4cfff3ea8fbaa2939088a0d1aa99d4e75f3edb1b44e5be6dd2e8d49fd423820c"
    hash_2021_trojan_AgentSig_bgmodio = "4ed5c7939fdaa8ca9cfc6cd0dfe762bb68b58adb434f98c1a28aae53c3b96b00"
    hash_2021_trojan_IAUQISY_rwrai = "5eb69f3b46a0df45f5e4f2c0beede4a86f9aace3870dd8db28bc6521e69f363b"
    hash_2021_trojan_ShellCode_shelma = "ae70ca051f29b058f18ed7aef33b750ddec69d05d08801cf3f99b121e41c0c4f"
    hash_2021_trojan_r002c0whf23_sxltr = "cb8d3fe305a2acaa34ebd37472fe4a966ed238e09d7f77164a1f53d850ea0294"
    hash_2021_trojan_GetShell_shellcode_ConnectBack = "de595779400e250b2275e7ecf9291879d26b29a71868984491b633f5de1362b8"
    hash_2021_trojan_GetShell_shellcode_94 = "eac3bb07ccd2e505af4bc74b9bef2886bf82b37c5820d9fcef673b4e246b2308"
    hash_2021_trojan_GetShell_expl = "ecaed171d4f088948908b2077fbcfe4ab94744b9df840befc9004376eeaff165"
    hash_2021_trojan_Mirai_Generica_zdhck = "f72a6f38886d4447e5c98fafb5c7249b1325d9f8f3833065bffeb6e46ef771ea"
  condition:
    filesize < 8192 and uint32(0) == 1179403647
}

rule impossibly_small_macho_program {
  meta:
    warning = "Many false positives if Java bytecode is included"
    hash_2019_Macma_CDDS_at = "341bc86bc9b76ac69dca0a48a328fd37d74c96c2e37210304cfa66ccdbe72b27"
    hash_2017_DevilRobber = "868926dc8773abddb806327b3ca9928e9d76a32abd273ea16ed73f4286260724"
    hash_2017_trojan_Quimitchin_Java = "a94dd8bfca34fd6ca3a475d6be342d236b39fbf0c2ab90b2edff62bcdbbe5d37"
    hash_2021_trojan_Java_Adwind = "cb3387ee7ae54b69f829b42690bef10e5efbdb7463f0f92cc896989b826344fd"
    hash_2021_oBSrz_AES = "d3cb413ca4f21bdce73ab1db40caa4951cf2e63012a01849a81f72d37113f2dd"
  strings:
    $not_jar = "META-INF/"
    $not_dwarf = "_DWARF"
    $not_kext = "_.SYMDEF SORTED"
  condition:
    filesize < 16384 and (uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178) and none of ($not*)
}
