

rule malware_unknown_machOdownloader {
     meta:
        description = "Mach-O malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "3266e99f14079b55e428193d5b23aa60862fe784ac8b767c5a1d49dfe80afeeb "

     strings:
        $str1 = "DiagPeersHelper" ascii
        $str2 = "DiagnosticsPeer" ascii
        $str3 = "ticsPeer/" ascii

        /*
        48 B9 3F 72 65 73 70 6F 6E 73       mov     rcx, 736E6F707365723Fh
        */
        $func0 = { 48 B9 3F 72 65 73 70 6F 6E 73 }

        /*
        48 B8 74 61 72 20 7A 78 76 66       mov     rax, 6676787A20726174h
        */
        $func1 = { 48 B8 74 61 72 20 7A 78 76 66 }

        /*
        E8 60 04 00 00                      call    _strlen
        C7 84 05 20 E7 FF FF 27 20 2D 43    mov     dword ptr [rbp+rax+shellcmd], 432D2027h
        C7 84 05 23 E7 FF FF 43 20 27 00    mov     dword ptr [rbp+rax+shellcmd+3], 272043h
        48 89 DF                            mov     rdi, rbx        ; __s1
        4C 89 E6                            mov     rsi, r12        ; __s2
        E8 33 04 00 00                      call    _strcat
        48 89 DF                            mov     rdi, rbx        ; __s
        E8 37 04 00 00                      call    _strlen
        */
        $func2 = { E8 [4] C7 84 05 [4] 27 20 2D 43 C7 84 05 [4] 43 20 27 00 48 89 DF 4C 89 E6 E8 33 04 00 00 }

     condition: 
        (uint32(0) == 0xfeedface or /* 32 bit */
         uint32(0) == 0xcefaedfe or /* NXSwapInt(MH_MAGIC */
         uint32(0) == 0xfeedfacf or /* 64 bit */
         uint32(0) == 0xcffaedfe or /* NXSwapInt(MH_MAGIC_64) */
         uint32(0) == 0xcafebabe or /* FAT, Java */
         uint32(0) == 0xbebafeca or /* NXSwapInt(FAT_MAGIC) */
         uint32(0) == 0xcafebabf or /* FAT 64 bit */
         uint32(0) == 0xbfbafeca )  /* NXSwapLong(FAT_MAGIC_64) */
        and (filesize < 10MB)
        and ( ( 2 of ($str*) ) or ( 2 of ($func*) ))
}
