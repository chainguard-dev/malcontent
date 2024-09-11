rule malware_droplink_str {
     meta:
        description = "malware using dropbox api(TRANSBOX, PLUGBOX)"
        author = "JPCERT/CC Incident Response Group"
        hash = "bdc15b09b78093a1a5503a1a7bfb487f7ef4ca2cb8b4d1d1bdf9a54cdc87fae4"
        hash = "6e5e2ed25155428b8da15ac78c8d87d2c108737402ecba90d70f305056aeabaa"

     strings:
        $data1 = "%u/%u_%08X_%u_%u.jpg" ascii wide
        $data2 = "%u/%u.jpg" ascii wide
        $data3 = "%u/%s" ascii wide
        $data4 = "%u/%u.3_bk.jpg"
        $data5 = "%u/%u.2_bk.jpg" ascii wide
        $data6 = "%u/%u_%08X_%d.jpg" ascii wide
        $data7 = "%s\",\"mode\":\"overwrite" ascii wide
        $data8 = "Dropbox-API-Art-Type:" ascii wide
        $data9 = "/2/files/upload" ascii wide
        $data10 = "Dropbox-API-Arg: {\"path\":\"/" ascii wide
        $data11 = "/oauth2/token" ascii wide
        $data12 = "LoadPlgFromRemote.dll" ascii wide
        $data13 = "FILETRANDLL.dll" ascii wide
        $data14 = "NVIDLA" ascii wide
        $data15 = "start.ini" ascii wide
        $data16 = "RunMain" ascii wide
        $data17 = "cfg.png" ascii wide
        $data18 = "DWrite.dll" ascii wide
        $pdb1 = "\\\\daddev\\office10\\2609.0\\setup\\x86\\ship\\program files\\common files\\microsoft shared\\office10\\1033\\DWINTLO.PDB" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize<1MB and
       (1 of ($pdb*) or 5 of ($data*))
}

rule malware_RestyLink_lnk {
     meta:
        description = "RestyLink lnk file"
        author = "JPCERT/CC Incident Response Group"
        hash = "90a223625738e398d2cf0be8d37144392cc2e7d707b096a7bfc0a52b408d98b1"
        hash = "9aa2187dbdeef231651769ec8dc5f792c2a9a7233fbbbcf383b05ff3d6179fcf"
        hash = "3feb9275050827543292a97cbf18c50c552a1771c4423c4df4f711a39696ed93"

     strings:
        $cmd1 = "C:\\Windows\\System32\\cmd.exe" wide
        $cmd2 = "Windows\\system32\\ScriptRunner.exe" wide
        $command1 = "/c set a=start winword.exe /aut&&set" wide
        $command2 = "&&set n=omation /vu /q&&cmd /c %a%%n% %m%" wide
        $command3 = "-appvscript explorer.exe https://" wide
        $command4 = "-appvscript curl.exe -s https://" wide

     condition:
       uint16(0) == 0x004c and
       filesize<100KB and
       1 of ($cmd*) and
       1 of ($command*)
}


rule restylink_Secur32_dll_downloader {
    meta:
        description = "Hunting no stripped Binaries by AutoYara4ELFsig JPCERT/CC"
        author = "AutoYara4ELFsig"
        rule_usage = "Hunting"
        hash = "107426B7B30D613E694F9153B415037C4E8194B7E7C96F0760EB59DE8F349809"

    strings:
        /* Function Address: 0x1800011b0 : mal_main
        41 B8 00 20 00 00                   mov     r8d, 2000h
        48 8B D3                            mov     rdx, rbx
        49 8B CE                            mov     rcx, r14
        FF D6                               call    rsi
        B9 64 00 00 00                      mov     ecx, 64h ; 'd'
        FF D7                               call    rdi
        48 81 C3 00 20 00 00                add     rbx, 2000h
        */
        $func0 = { 41 B8 00 20 00 00 48 8B D3 49 8B CE FF D6 B9 64 00 00 00 FF D7 48 81 C3 00 20 00 00 }

        /* Function Address: 0x1800011b0 : mal_main
        44 8B C7                mov     r8d, edi
        BB A3 00 00 00          mov     ebx, 0A3h
        0F 1F 80 00 00 00 00    nop     dword ptr [rax+00000000h]
        FF C0                   inc     eax
        25 FF 00 00 80          and     eax, 800000FFh
        7D 09                   jge     short loc_180001592
        FF C8                   dec     eax
        0D 00 FF FF FF          or      eax, 0FFFFFF00h
        FF C0                   inc     eax
        48 63 C8                movsxd  rcx, eax
        */
        $func1 = { 44 8B C7 BB A3 00 00 00 0F 1F 80 00 00 00 00 FF C0 25 FF 00 00 80 7D 09 FF C8 0D 00 FF FF FF FF C0 48 63 C8 }

        /*
          RC4key  j#ghsj@%dhg#87u*#RYCIHfvd )7
        */
        $func2 = { 6A 23 67 68 73 6A 40 25  64 68 67 23 38 37 75 2A 23 52 59 43 49 48 66 76  64 20 29 37 }

        /*
          c2
        */
        $func3 = { 61 62 63 2E 6D 62 75 73 61 62 63 2E 63 6F 6D 00}

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize < 1MB)
        and ( 1 of ($func*) )
}
