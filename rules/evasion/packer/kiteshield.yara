rule kiteshield : high {
  meta:
    author = "Alex.Turing, Wang Hao"
    date = "2024-05-28"
    description = "Rule to identify files packed by Kiteshield"
    hash_amdc6766_1 = "2c80808b38140f857dc8b2b106764dd8"
    hash_amdc6766_2 = "909c015d5602513a770508fa0b87bc6f"
    hash_amdc6766_3 = "5ea33d0655cb5797183746c6a46df2e9"
    hash_gafgyt = "4afedf6fbf4ba95bbecc865d45479eaf"
    hash_winnti = "f5623e4753f4742d388276eaee72dea6"
    reference = "https://blog.xlab.qianxin.com/kiteshield_packer_is_being_abused_by_linux_cyber_threat_actors"
    tool = "Kiteshield"
    tool_repository = "https://github.com/GunshipPenguin/kiteshield"
    
  strings: 
    $loader_jmp = {31 D2 31 C0 31 C9 31 F6 31 FF 31 ED 45 31 C0 45 31 C9 45 31 D2 45 31 DB 45 31 E4 45 31 ED 45 31 F6 45 31 FF 5B FF E3}
    // "/proc/%d/status"
    $loader_s1 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb e5 e2}
    // "TracerPid:"
    $loader_s2 = {d7 f6 e4 e5 e2 fa d9 e3 ef b6}
    // "/proc/%d/stat"
    $loader_s3 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb}
    // "LD_PRELOAD"
    $loader_s4 = {cf c0 da d6 d5 cd c5 c5 ca c8}
    // "LD_AUDIT"
    $loader_s5 = {cf c0 da c7 d2 cc c0 de}
    // "LD_DEBUG"
    $loader_s6 = {cf c0 da c2 c2 ca dc cd}
    // "0123456789abcdef"
    $loader_s7 = {b3 b5 b7 b5 b3 bd bf bd b3 b5 ec ec ec f4 f4 f4}

  condition:
    $loader_jmp and all of ($loader_s*) and
    // ELF Magic at offset 0
    uint32(0) == 0x464c457f and
    // ET_EXEC at offset 16
    uint16(16) == 0x0002 and
    (
        // x86_64 at offset 18
        uint16(18) == 0x003e or
        // aarch64 at offset 18
        uint16(18) == 0x00b7
    )
}
