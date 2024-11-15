rule Lazarus_BILDINGCAN_RC4 {
    meta:
        description = "BILDINGCAN_RC4 in Lazarus"
        author = "JPCERT/CC Incident Response Group"


    strings:
        $customrc4 = { 75 C0 41 8B D2 41 BB 00 0C 00 00 0F 1F 80 00 00 00 00 }
            // jnz     short loc_180002E60
            // mov     edx, r10d
            // mov     r11d, 0C00h
            //nop     dword ptr [rax+00000000h]
         $id = "T1B7D95256A2001E" ascii
         $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
         $post = "id=%s%s&%s=%s&%s=%s&%s=" ascii
         $command = "%s%sc \"%s > %s 2>&1" ascii

     condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_AES {
    meta:
        description = "BILDINGCAN_AES in Lazarus"
        author = "JPCERT/CC Incident Response Group"


    strings:
        $AES = { 48 83 C3 04 30 43 FC 0F B6 44 1F FC 30 43 FD 0F B6 44 1F FD 30 43 FE 0F B6 44 1F FE 30 43 FF 48 FF C9 }
        $pass = "RC2zWLyG50fPIPkQ" wide
        $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
        $confsize = { 48 8D ?? ?? ?? ?? 00 BA F0 06 00 00 E8 }
        $buffsize = { 00 00 C7 ?? ?? ??  B8 8E 03 00 }
        $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

     condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_module {
    meta:
        description = "BILDINGCAN_AES module in Lazarus"
        author = "JPCERT/CC Incident Response Group"

    strings:
      $cmdcheck1 = { 3D ED AB 00 00 0F ?? ?? ?? 00 00 3D EF AB 00 00 0F ?? ?? ?? 00 00 3D 17 AC 00 00 0F ?? ?? ?? 00 00 }
      $cmdcheck2 = { 3D 17 AC 00 00 0F ?? ?? ?? 00 00 3D 67 EA 00 00 0F ?? ?? ?? 00 00 }
      $recvsize = { 00 00 41 81 F8 D8 AA 02 00 }
      $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
      $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

    condition:
      uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_Torisma_strvest {
    meta:
        description = "Torisma in Lazarus"
        author = "JPCERT/CC Incident Response Group"


    strings:
         $post1 = "ACTION=NEXTPAGE" ascii
         $post2 = "ACTION=PREVPAGE" ascii
         $post3 = "ACTION=VIEW" ascii
         $post4 = "Your request has been accepted. ClientID" ascii
         $password = "ff7172d9c888b7a88a7d77372112d772" ascii
         $vestt = { 4F 70 46 DA E1 8D F6 41 }
         $vestsbox = { 07 56 D2 37 3A F7 0A 52 }
         $vestrns = { 41 4B 1B DD 0D 65 72 EE }

     condition:
         uint16(0) == 0x5a4d and (all of ($post*) or $password or all of ($vest*))
}

rule Lazarus_LCPDot_strings {
    meta:
        description = "LCPDot in Lazarus"
        author = "JPCERT/CC Incident Response Group"


    strings:
         $ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
         $class = "HotPlugin_class" wide
         $post = "Cookie=Enable&CookieV=%d&Cookie_Time=64" ascii

     condition:
         uint16(0) == 0x5a4d and all of them
}

rule Lazarus_Torisma_config {
    meta:
        description = "Torisma config header"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $header = { 98 11 1A 45 90 78 BA F9 4E D6 8F EE }

     condition:
        all of them
}

rule Lazarus_loader_thumbsdb {
    meta:
        description = "Loader Thumbs.db malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $switchcase = { E8 ?? ?? ?? ?? 83 F8 64 74 ?? 3D C8 00 00 00 74 ?? 3D 2C 01 00 00 75 ?? E8 ?? ?? ?? ?? B9 D0 07 00 00 E8 }

     condition:
        all of them
}

rule Lazarus_Comebacker_strings {
    meta:
        description = "Comebacker malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $postdata1 = "%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%s" ascii
        $postdata2 = "Content-Type: application/x-www-form-urlencoded" wide
        $postdata3 = "Connection: Keep-Alive" wide
        $key  = "5618198335124815612315615648487" ascii
        $str1 = "Hash error!" ascii wide
        $str2 = "Dll Data Error|" ascii wide
        $str3 = "GetProcAddress Error|" ascii wide
        $str4 = "Sleeping|" ascii wide
        $str5 = "%s|%d|%d|" ascii wide

     condition:
        all of ($postdata*) or $key or all of ($str*)
}

rule Lazarus_VSingle_strings {
     meta:
        description = "VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"



     strings:
        $encstr1 = "Valefor was uninstalled successfully." ascii wide
        $encstr2 = "Executable Download Parameter Error" ascii wide
        $encstr3 = "Plugin Execute Result" ascii wide
        $pdb = "G:\\Valefor\\Valefor_Single\\Release\\VSingle.pdb" ascii
        $str1 = "sonatelr" ascii
        $str2 = ".\\mascotnot" ascii
        $str3 = "%s_main" ascii
        $str4 = "MigMut" ascii
        $str5 = "lkjwelwer" ascii
        $str6 = "CreateNamedPipeA finished with Error-%d" ascii
        $str7 = ".\\pcinpae" ascii
        $str8 = { C6 45 80 4C C6 45 81 00 C6 45 82 00 C6 45 83 00 C6 45 84 01 C6 45 85 14 C6 45 86 02 C6 45 87 00 }
        $xorkey1 = "o2pq0qy4ymcrbe4s" ascii wide
        $xorkey2 = "qwrhcd4pywuyv2mw" ascii wide
        $xorkey3 = "3olu2yi3ynwlnvlu" ascii wide
        $xorkey4 = "uk0wia0uy3fl3uxd" ascii wide

     condition:
        all of ($encstr*) or $pdb or 1 of ($xorkey*) or 3 of ($str*)
}

rule Lazarus_ValeforBeta_strings {
    meta:
        description = "ValeforBeta malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $str0 = "cmd interval: %d->%d" ascii wide
        $str1 = "script interval: %d->%d" ascii wide
        $str2 = "Command not exist. Try again." ascii wide
        $str3 = "successfully uploaded from %s to %s" ascii wide
        $str4 = "success download from %s to %s" ascii wide
        $str5 = "failed with error code: %d" ascii wide

     condition:
        3 of ($str*)
}

//import "pe"

//rule Lzarus_2toy_sig {
//   meta:
//      description = "Lazarus using signature 2 TOY GUYS LLC"
//      date = "2021-02-03"
//      author = "JPCERT/CC Incident Response Group"
//      hash1 = "613f1cc0411485f14f53c164372b6d83c81462eb497daf6a837931c1d341e2da"
//      hash2 = "658e63624b73fc91c497c2f879776aa05ef000cb3f38a340b311bd4a5e1ebe5d"

//   condition:
//      uint16(0) == 0x5a4d and
//      for any i in (0 .. pe.number_of_signatures) : (
//         pe.signatures[i].issuer contains "2 TOY GUYS LLC" and
//         pe.signatures[i].serial == "81:86:31:11:0B:5D:14:33:1D:AC:7E:6A:D9:98:B9:02"
//      )
//}

rule Lazarus_packer_code {
    meta:
        description = "Lazarus using packer"
        author = "JPCERT/CC Incident Response Group"



     strings:
        $code = { 55 8B EC A1 ?? ?? ?? 00 83 C0 01 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 ( 01 | 02 | 03 | 04 | 05 ) 76 16 8B 0D ?? ?? ?? 00 83 E9 01 89 0D ?? ?? ?? 00 B8 ?? ?? ?? ?? EB  }
     condition:
        all of them
}

rule Lazarus_Kaos_golang {
    meta:
        description = "Kaos malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"



     strings:
        $gofunc1 = "processMarketPrice" ascii wide
        $gofunc2 = "handleMarketPrice" ascii wide
        $gofunc3 = "EierKochen" ascii wide
        $gofunc4 = "kandidatKaufhaus" ascii wide
        $gofunc5 = "getInitEggPrice" ascii wide
        $gofunc6 = "HttpPostWithCookie" ascii wide

     condition:
        4 of ($gofunc*)
}

rule Lazarus_VSingle_elf {
    meta:
        description = "ELF_VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $code1 = { C6 85 ?? ?? FF FF 26 C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 73 } // &uis
        $code2 = { C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 66 C6 85 ?? ?? FF FF 77 } // ufw
        $code3 = { C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 73 C6 85 ?? ?? FF FF 7C C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 78 } // %s|%x
        $code4 = { C6 85 ?? ?? FF FF 4D C6 85 ?? ?? FF FF 6F C6 85 ?? ?? FF FF 7A C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 61 C6 85 ?? ?? FF FF 2F } // Mozilla
        $code5 = { C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 73 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 } // %s%1u%1u
     condition:
        3 of ($code*)
}

rule Lazarus_packer_upxmems {
    meta:
        description = "ELF malware packer based UPX in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $code1 = { 47 2C E8 3C 01 77 [10-14] 86 C4 C1 C0 10 86 C4 }
                                       // inc edi
                                       // sub al, 0E8h
                                       // cmp al, 1
                                       // xchg al, ah
                                       // rol eax, 10h
                                       // xchg al, ah
        $code2 = { 81 FD 00 FB FF FF 83 D1 02 8D } // cmp ebp, FFFFFB00h    adc ecx, 2
        $sig = "MEMS" ascii
     condition:
        all of ($code*) and #sig >= 3 and uint32(0x98) == 0x534d454d
}

rule Lazarus_httpbot_jsessid {
    meta:
        description = "Unknown HTTP bot in Lazarus"
        author = "JPCERT/CC Incident Response Group"


     strings:
        $jsessid = "jsessid=%08x%08x%08x" ascii
        $http = "%04x%04x%04x%04x" ascii
        $init = { 51 68 ?? ?? ?? 00 51 BA 04 01 00 00 B9 ?? ?? ?? 00 E8 }
        $command = { 8B ?? ?? 05 69 62 2B 9F 83 F8 1D 0F ?? ?? ?? 00 00 FF}

     condition:
        $command or ($jsessid and $http and #init >= 3)
}

rule Lazarus_tool_smbscan {
    meta:
        description = "SMB scan tool in Lazarus"
        author = "JPCERT/CC Incident Response Group"



     strings:
        $toolstr1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" ascii
        $toolstr2 = "%s%-30s%I64d\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr3 = "%s%-30s(DIR)\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr4 = "%s U/P not Correct! - %d" ascii
        $toolstr5 = "%s %-20S%-30s%S" ascii
        $toolstr6 = "%s - %s:(Username - %s / Password - %s" ascii

     condition:
        4 of ($toolstr*)
}

rule Lazarus_simplecurl_strings {
    meta:
        description = "Tool of simple curl in Lazarus"
        author = "JPCERT/CC Incident Response Group"

     strings:
        $str1 = "Usage: [application name].exe url filename" ascii
        $str2 = "completely succeed!" ascii
        $str3 = "InternetOpenSession failed.." ascii
        $str4 = "HttpSendRequestA failed.." ascii
        $str5 = "HttpQueryInfoA failed.." ascii
        $str6 = "response code: %s" ascii
        $str7 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :" ascii
     condition:
        4 of ($str*)
}

rule Lazarus_Dtrack_code {
     meta:
        description = "Dtrack malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "2bcb693698c84b7613a8bde65729a51fcb175b04f5ff672811941f75a0095ed4"
        hash = "467893f5e343563ed7c46a553953de751405828061811c7a13dbc0ced81648bb"

     strings:
        $rc4key1 = "xwqmxykgy0s4"
        $rc4key2 = "hufkcohxyjrm"
        $rc4key3 = "fm5hkbfxyhd4"
        $rc4key4 = "ihy3ggfgyohx"
        $rc4key5 = "fwpbqyhcyf2k"
        $rc4key6 = "rcmgmg3ny3pa"
        $rc4key7 = "a30gjwdcypey"
        $zippass1 = "dkwero38oerA^t@#"
        $zippass2 = "z0r0f1@123"
        $str1 = "Using Proxy"
        $str2 = "Preconfig"
        $str3 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :"
        $str4 = "%02X:%02X:%02X:%02X:%02X:%02X"
        $str5 = "%s\\%c.tmp"
        $code = { 81 ?? EB 03 00 00 89 ?? ?? ?? FF FF 83 ?? ?? ?? FF FF 14 0F 87 EA 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($rc4key*) or 1 of ($zippass*) or (3 of  ($str*) and $code))
}

rule Lazarus_keylogger_str {
     meta:
        description = "Keylogger in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e0567863b10e9b1ac805292d30626ea24b28ee12f3682a93d29120db3b77a40a"

     strings:
        $mutex = "c2hvcGxpZnRlcg"
        $path = "%APPDATA%\\\\Microsoft\\\\Camio\\\\"
        $str = "[%02d/%02d/%d %02d:%02d:%02d]"
        $table1 = "CppSQLite3Exception"
        $table2 = "CppSQLite3Query"
        $table3 = "CppSQLite3DB"
        $table4 = "CDataLog"
        $table5 = "CKeyLogger"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       4 of them
}

rule Lazarus_DreamJob_doc2021 {
     meta:
        description = "Malicious doc used in Lazarus operation Dream Job"
        author = "JPCERT/CC Incident Response Group"




     strings:
        $peheadb64 = "dCBiZSBydW4gaW4gRE9TIG1vZGU"
        $command1 = "cmd /c copy /b %systemroot%\\system32\\"
        $command2 = "Select * from Win32_Process where name"
        $command3 = "cmd /c explorer.exe /root"
        $command4 = "-decode"
        $command5 = "c:\\Drivers"
        $command6 = "explorer.exe"
        $command7 = "cmd /c md"
        $command8 = "cmd /c del"

     condition:
       uint16(0) == 0xCFD0 and
       $peheadb64 and 4 of ($command*)
}

rule Lazarus_boardiddownloader_code {
     meta:
        description = "boardid downloader in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "fe80e890689b0911d2cd1c29196c1dad92183c40949fe6f8c39deec8e745de7f"

     strings:
        $enchttp = { C7 ?? ?? 06 1A 1A 1E C7 ?? ?? 1D 54 41 41 }
        $xorcode = { 80 74 ?? ?? 6E 80 74 ?? ?? 6E (48 83|83) ?? 02 (48|83) }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}

rule Lazarus_obfuscate_string {
    meta:
        description = "Strings contained in obfuscated files used by Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"

    strings:
        $str1 = { 2D 41 72 67 75 6D 65 6E 74 4C 69 73 74 20 27 5C 22 00 }
        $str2 = "%^&|," wide
        $str3 = "SeDebugPrivilege" wide

    condition:
        uint16(0) == 0x5a4d and
        filesize > 1MB and
        all of them
}

rule Lazarus_VSingle_github {
     meta:
        description = "VSingle using GitHub in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "199ba618efc6af9280c5abd86c09cdf2d475c09c8c7ffc393a35c3d70277aed1"
        hash = "2eb16dbc1097a590f07787ab285a013f5fe235287cb4fb948d4f9cce9efa5dbc"

     strings:
        $str1 = "Arcan3" ascii wide fullword
        $str2 = "Wr0te" ascii wide fullword
        $str3 = "luxuryboy" ascii wide fullword
        $str4 = "pnpgather" ascii wide fullword
        $str5 = "happyv1m" ascii wide fullword
        $str6 = "laz3rpik" ascii wide fullword
        $str7 = "d0ta" ascii wide fullword
        $str8 = "Dronek" ascii wide fullword
        $str9 = "Panda3" ascii wide fullword
        $str10 = "cpsponso" ascii wide fullword
        $str11 = "ggo0dlluck" ascii wide fullword
        $str12 = "gar3ia" ascii wide fullword
        $str13 = "wo0d" ascii wide fullword
        $str14 = "tr3e" ascii wide fullword
        $str15 = "l0ve" ascii wide fullword
        $str16 = "v0siej" ascii wide fullword
        $str17 = "e0vvsje" ascii wide fullword
        $str18 = "polaris" ascii wide fullword
        $str19 = "grav1ty" ascii wide fullword
        $str20 = "w1inter" ascii wide fullword

     condition:
       (uint32(0) == 0x464C457F and
       8 of ($str*)) or
       (uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       8 of ($str*))
}

rule Lazarus_BTREE_str {
     meta:
        description = "BTREE malware using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "4fb31b9f5432fd09f1fa51a35e8de98fca6081d542827b855db4563be2e50e58"

     strings:
        $command1 = "curl -A cur1-agent -L %s -s -d da" ascii wide
        $command2 = "cmd /c timeout /t 10 & rundll32 \"%s\" #1" ascii wide
        $command3 = "rundll32.exe %s #1 %S" ascii wide
        $command4 = "%s\\marcoor.dll" ascii wide
        $rc4key = "FaDm8CtBH7W660wlbtpyWg4jyLFbgR3IvRw6EdF8IG667d0TEimzTiZ6aBteigP3" ascii wide

     condition:
       2 of ($command*) or $rc4key
}

//import "pe"
//import "hash"

//rule Lazarus_PDFIcon {
//    meta:
//        description = "PDF icon used in PE file by Lazarus"
//        author = "JPCERT/CC Incident Response Group"
//        hash = "e5466b99c1af9fe3fefdd4da1e798786a821c6d853a320d16cc10c06bc6f3fc5"

//    condition:
//        for any i in (0..pe.number_of_resources - 1) : (
//            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "b3e0e069d00fb2a746b7ed1eb3d6470772a684349800fc84bae9f40c8a43d87a"
//        )
//}

rule Lazarus_msi_str {
    meta:
        description = "msi file using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "f0b6d6981e06c7be2e45650e5f6d39570c1ee640ccb157ddfe42ee23ad4d1cdb"
	
    strings:
        $magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
        $s1 = "New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 300)" ascii wide
        $s2 = "New-ScheduledTaskAction -Execute \"c:\\windows\\system32\\pcalua.exe" ascii wide
        $s3 = "function sendbi(pd)" ascii wide
        $s4 = "\\n\\n\"+g_mac()+\"\\n\\n\"+g_proc()" ascii wide

     condition:
       $magic at 0 and 2 of ($s*)
}

rule Lazarus_downloader_code {
     meta:
        description = "Lazarus downloader"
        author = "JPCERT/CC Incident Response Group"
        hash = "faba4114ada285987d4f7c771f096e0a2bc4899c9244d182db032acd256c67aa"

     strings:
        $jmp = { 53 31 c0 50 50 50 50 50 C7 ?? ?? 00 00 00 00 EB 00 }
        $count = { 00 00 EB 00 B8 FF 59 62 02 3B 05 ?? ?? ?? 00 }
        $api = "InitOnceExecuteOnce" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize < 200KB and
       all of them
}

rule Lazarus_magicpoint_code {
     meta:
        description = "magicpoint bot using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "6f11c52f01e5696b1ac0faf6c19b0b439ba6f48f1f9851e34f0fa582b09dfa48"

     strings:
        $strPost1 = "mpVI=%s" ascii
		  $strPost2 = "mpCMD=%s&mpVID=%s" ascii
		  $strPost3 = "mpVCR=%s&mpID=%s" ascii
        $strMsg1 = "Error creating pipe" ascii
        $strMsg2 = "Error creating process" ascii
        $strFormat = "%c%c%c%s%c%s" ascii
		  $strUA = "Mozilla/88.0" ascii
	     $strMutex = "LGMUQTW" ascii
		  $strData = "xz36" ascii
		  $strcmd = "cmd.exe /c %s" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       4 of ($str*)
}

rule lazarus_dbgsymbols_str{
       meta:
         description = "Exploit tools in Lazarus"
         author = "JPCERT/CC Incident Response Group"
         hash = "50869d2a713acf406e160d6cde3b442fafe7cfe1221f936f3f28c4b9650a66e9" 

       strings:
         $str1 = "getsymbol" nocase
         $str2 = "dbgsymbol.com" wide
         $str3 = "c:\\symbols" wide
         $str4 = "symchk.exe /r /if %s /s SRV*%s*%s" wide
         $str5 = "Symbol Download Finished!" wide
	      $filename = "symbolcheck.dll" wide

       condition:
         uint16(0) == 0x5A4D and
         uint32(uint32(0x3c)) == 0x00004550 and
         3 of ($str*) and all of ($filename)
}

rule Lazarus_npmLoader_dll {
     meta:
        description = "npmLoaderDll using Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "b4c8c149005a43ae043038d4d62631dc1a0f57514c7cbf4f7726add7ec67981a"
        hash = "eb8756ace46662a031c1d2422a91f0725ea7c4de74bfff4fce2693e7967be16e"
        hash = "aec915753612bb003330ce7ffc67cfa9d7e3c12310f0ecfd0b7e50abf427989a"

     strings:
        $jnkcode = { 66 66 66 66 ?? ?? ?? ?? 00 00 00 00 00 }
        $enccode1 = { 81 E2 FF 03 00 00 41 81 E1 FF 03 00 00 81 E7 FF 03 00 00 81 E1 FF 03 00 00 }
        $enccode2 = { 48 33 D1 8B C1 41 C1 CA 0A C1 C0 09 81 E2 FF 03 00 00 44 33 D0 }
        $pdb1 = "F:\\workspace\\CBG\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
        $pdb2 = "F:\\workspace\\CBG\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
        $pdb3 = "D:\\workspace\\CBG\\Windows\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide
        $pdb4 = "npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (
        (1 of ($pdb*)) or ($jnkcode and all of ($enccode*))
       )
}