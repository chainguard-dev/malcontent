import "elf"

rule malware_GobRAT {
    meta:
        description = "GobRAT"
        author = "JPCERT/CC Incident Response Group"
        hash = "C9345377CAB1A878803C3E3450BE06E0CF18B94E930090DD56F4641812FC4858"

    strings:
        /* Function Address: 0x76dac0 : main.e2dbcOYHJPQH5_connect_command
        BE 01 00 00 00                      mov     esi, 1
        49 89 C0                            mov     r8, rax
        49 89 D9                            mov     r9, rbx
        31 C0                               xor     eax, eax
        48 89 CB                            mov     rbx, rcx
        48 89 D1                            mov     rcx, rdx
        */
        $func0 = { BE 01 00 00 00 49 89 C0 49 89 D9 31 C0 48 89 CB 48 89 D1 }

        /* Function Address: 0x769b60 : main.main
        48 FF CF                            dec     rdi
        48 89 FE                            mov     rsi, rdi
        48 F7 DF                            neg     rdi
        48 C1 FF 3F                         sar     rdi, 3Fh
        83 E7 10                            and     edi, 10h
        */
        $func1 = { 48 FF CF 48 89 FE 48 F7 DF 48 C1 FF 3F 83 E7 10 }

        /* Function Address: 0x76a9a0 : main.y8IOk9QWrX
        48 89 C8                            mov     rax, rcx
        48 89 FB                            mov     rbx, rdi
        B9 42 00 00 00                      mov     ecx, 42h ; 'B'
        BF ED 01 00 00                      mov     edi, 1EDh
        */
        $func2 = { 48 89 C8 48 89 FB B9 42 00 00 00 BF ED 01 00 00 }

        /* Function Address: 0x76ef80 : main.iOYnTYA4FE6.func1
        48 81 C4 90 00 00 00                add     rsp, 90h
        C3                                  retn
        48 89 C1                            mov     rcx, rax
        BA 14 00 00 00                      mov     edx, 14h
        */
        $func3 = { 48 81 C4 90 00 00 00 C3 48 89 C1 BA 14 00 00 00 }

        /* Function Address: 0x779520 : main.xdtfT9WTAtjGH
        48 89 CA                            mov     rdx, rcx
        48 69 CB 00 CA 9A 3B                imul    rcx, rbx, 3B9ACA00h
        81 E2 FF FF FF 3F                   and     edx, 3FFFFFFFh
        48 63 D2                            movsxd  rdx, edx
        48 01 D1                            add     rcx, rdx
        48 BA 00 00 1A 3D EB 03 B2 A1       mov     rdx, 0A1B203EB3D1A0000h
        */
        $func4 = { 48 89 CA 48 69 CB 00 CA 9A 3B 81 E2 FF FF FF 3F 48 63 D2 48 01 D1 48 BA 00 00 1A 3D EB 03 B2 A1 }

        /* Function Address: 0x76f340 : main.t3GG7N1fn74_tuj
        48 89 D8                            mov     rax, rbx
        FF D1                               call    rcx
        B9 0E 00 00 00                      mov     ecx, 0Eh
        48 89 C7                            mov     rdi, rax
        48 89 DE                            mov     rsi, rbx
        31 C0                               xor     eax, eax
        */
        $func5 = { 48 89 D8 FF D1 B9 0E 00 00 00 48 89 C7 48 89 DE 31 C0 }

        /* Function Address: 0x7767e0 : main.qt6QoJqDx
        48 81 C4 00 02 00 00                add     rsp, 200h
        C3                                  retn
        48 83 C2 30                         add     rdx, 30h ; '0'
        4C 89 DE                            mov     rsi, r11
        4C 89 D7                            mov     rdi, r10
        */
        $func6 = { 48 81 C4 00 02 00 00 C3 48 83 C2 30 4C 89 DE 4C 89 D7 }

        /* Function Address: 0x76f120 : main.tu7cdVpcuvOtFI_afterCmd
        31 FF                               xor     edi, edi
        BE 02 00 00 00                      mov     esi, 2
        41 B8 01 00 00 00                   mov     r8d, 1
        31 C9                               xor     ecx, ecx
        */
        $func7 = { 31 FF BE 02 00 00 00 41 B8 01 00 00 00 31 C9 }

        /* Function Address: 0x77c280 : main.FeX9At3YKp
        48 81 C4 F8 04 00 00                add     rsp, 4F8h
        C3                                  retn
        49 89 C1                            mov     r9, rax
        89 D0                               mov     eax, edx
        48 89 DA                            mov     rdx, rbx
        48 89 FB                            mov     rbx, rdi
        48 89 CF                            mov     rdi, rcx
        48 89 F1                            mov     rcx, rsi
        4C 89 C6                            mov     rsi, r8
        4D 89 C8                            mov     r8, r9
        */
        $func8 = { 48 81 C4 F8 04 00 00 C3 49 89 C1 89 D0 48 89 DA 48 89 FB 48 89 CF 48 89 F1 4C 89 C6 4D 89 C8 }

        /* Function Address: 0x77b820 : main.zpnsHbpz
        48 D1 E2                            shl     rdx, 1
        48 C1 EA 1F                         shr     rdx, 1Fh
        48 BE 80 7F B1 D7 0D 00 00 00       mov     rsi, 0DD7B17F80h
        48 01 F2                            add     rdx, rsi
        */
        $func9 = { 48 D1 E2 48 C1 EA 1F 48 BE 80 7F B1 D7 0D 00 00 00 48 01 F2 }

        /* Function Address: 0x77ea20 : main.gefjTYDL
        4C 29 C7                            sub     rdi, r8
        48 89 FA                            mov     rdx, rdi
        48 F7 DF                            neg     rdi
        49 C1 E0 02                         shl     r8, 2
        48 C1 FF 3F                         sar     rdi, 3Fh
        49 21 F8                            and     r8, rdi
        */
        $func10 = { 4C 29 C7 48 89 FA 48 F7 DF 49 C1 E0 02 48 C1 FF 3F 49 21 F8 }

        /* Function Address: 0x77b200 : main.umSY9oSz2zzLR_checkNetFlow
        48 89 F8                            mov     rax, rdi
        90                                  nop
        FF D1                               call    rcx
        B9 14 00 00 00                      mov     ecx, 14h
        48 89 C7                            mov     rdi, rax
        48 89 DE                            mov     rsi, rbx
        31 C0                               xor     eax, eax
        */
        $func11 = { 48 89 F8 90 FF D1 B9 14 00 00 00 48 89 C7 48 89 DE 31 C0 }

        /* Function Address: 0x785520 : main._ptr_QSRhXM0NX2M.bSAJf0JqL
        BF 00 20 00 00                      mov     edi, 2000h
        48 89 F9                            mov     rcx, rdi
        FF D2                               call    rdx
        66 90                               xchg    ax, ax
        48 85 DB                            test    rbx, rbx
        */
        $func13 = { BF 00 20 00 00 48 89 F9 FF D2 66 90 48 85 DB }

        /* Function Address: 0x785880 : main._ptr_QSRhXM0NX2M.w4qMdz7jv5jRv
        B9 0F 00 00 00                      mov     ecx, 0Fh
        BF 00 20 00 00                      mov     edi, 2000h
        FF D6                               call    rsi
        48 85 DB                            test    rbx, rbx
        */
        $func14 = { B9 0F 00 00 00 BF 00 20 00 00 FF D6 48 85 DB }

        /* Function Address: 0x781e20 : main.BdQy4w8Fi8
        48 81 C4 10 02 00 00                add     rsp, 210h
        C3                                  retn
        48 89 D9                            mov     rcx, rbx
        48 89 C3                            mov     rbx, rax
        */
        $func15 = { 48 81 C4 10 02 00 00 C3 48 89 D9 48 89 C3 }

    condition:
        (uint32(0) == 0x464C457F)
        and (elf.machine == elf.EM_X86_64)
        and (filesize > 2MB)
       and (filesize < 4MB)
       and ( 8 of ($func*) )
}


rule malware_GobRATLoader {
    meta:
        description = "GobRAT Loader ShellScript"
        author = "JPCERT/CC Incident Response Group"
        hash = "3e44c807a25a56f4068b5b8186eee5002eed6f26d665a8b791c472ad154585d1"

    strings:
        $str1 = "CACHEDEV3_DATA CACHEDEV2_DATA CACHEDEV1_DATA MD0_DATA"
        $str2 = "#clean old program cache"
        $str3 = "firewalld stop error"
        $str4 = "firewalld disable  error"
        $str5 = "CPU architecture: 8"
        $str6 = "#download elf with rate 200k"
        $str7 = "#kill old elf process"
        $str8 = "#normal daemon to hold backdoor running"
        $str9 = "#autorun own, insert to qnap autorun script"
        $str10 = "# insert ssh public backdoor"
        $str11 = "Pi5papdFA0M9z6AQoa9Y31ww65f8P5slNf1Q8vloVIwg"
        $str12 = "#set a daemon script"
        $str13 = "#autorun 2 "
        $str14 = "grep frpc |grep -v grep | awk"
        $str15 = "iptables error"

    condition:
        (filesize < 15KB)
        and ( 3 of ($str*) )
}
