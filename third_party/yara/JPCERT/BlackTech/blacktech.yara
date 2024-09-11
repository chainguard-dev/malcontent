rule BlackTech_PLEAD_mutex {
    meta:
      description = "PLEAD malware mutex strings"
      author = "JPCERT/CC Incident Response Group"
      hash = "6a49771dbb9830e1bdba45137c3a1a22d7964df26e02c715dd6e606f8da4e275"

    strings:
        $v1a = "1....%02d%02d%02d_%02d%02d...2"
        $v1b = "1111%02d%02d%02d_%02d%02d2222"
        $v1c = "%02d:%02d:%02d"
        $v1d = "%02d-%02d-%02d"

    condition:
        ($v1a or $v1b) and $v1c and $v1d
}

rule BlackTech_PLEAD_elf {
    meta:
        description = "ELF PLEAD"
        author = "JPCERT/CC Incident Response Group"
        hash = "f704303f3acc2fd090145d5ee893914734d507bd1e6161f82fb34d45ab4a164b"

    strings:
        $ioctl = "ioctl TIOCSWINSZ error"
        $class1 = "CPortForwardManager"
        $class2 = "CRemoteShell"
        $class3 = "CFileManager"
        $lzo = { 81 ?? FF 07 00 00 81 ?? 1F 20 00 00 }

    condition:
        3 of them
}

rule BlackTech_TSCookie_rat{
    meta:
      description = "TSCookie malware module"
      author = "JPCERT/CC Incident Response Group"
      hash = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"

    strings:
        $w1d = "Date: %s" wide
        $w1a = "[-] Failed to initialize **** API" wide
        $w1b = "IPv6Test" wide

    condition:
        all of them
}

rule BlackTech_TSCookie_UA {
    meta:
      description = "detect TSCookie in memory"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "memory scan"
      reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
      hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

    strings:
      $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
      $b1 = { 68 D4 08 00 00 }
      $d1 = { 68 78 0B 00 00 }
      $v1b = { 68 9C 95 1A 6E }
      $v1c = { 68 E6 17 8F 7B }
      $v1d = { C7 40 7C 92 5A 76 5D }
      $v1e = { C7 ?? ?? ?? ?? ?? 92 5A 76 5D }

    condition:
      ($v1 and ($b1 or $d1)) or ($v1b and $v1c and ($v1d or $v1e))
}

rule BlackTech_TSCookie_loader
{
    meta:
        description = "detect tscookie loader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "a800df1b8ffb4fbf42bccb4a8af31c7543de3bdba1207e703d6df464ec4398e6"
        hash2 = "b548a7ad37d241b7a7762bb84a3b0125772c469ef5f8e5e0ea190fa2458a018c"

    strings:
        $rc4key = {C7 [1-6] 92 5A 76 5D}
        $rc4loop = {3D 00 01 00 00}

    condition:
        (uint16(0) == 0x5A4D) and
        (filesize<2MB) and
        all of ($rc4*)
}

rule BlackTech_TSCookie_loader_pdb
{
    meta:
        description = "detect tscookie loader pdb"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "cc424006225d4dfcb7a6287bccd9c338d570c733b5ffcbf77be8e23a4cc20f6e"
        hash2 = "794f942c3298a43712f873cc20882d8138f75105fb151f99c5802f91f884ef04"

     strings:
        $pdb1 = "D:\\[0]MyATS-TEMP-Loading-"
        $pdb2 = "ATS-TEMP-Loader-"
        $pdb3 = "MyFuckers\\MyFuckers_"
        $pdb4 = "MyFuckersService8\\MyFuckers_"

     condition:
        uint16(0) == 0x5A4D and
        ($pdb1 or $pdb2 or $pdb3 or $pdb4)
}

rule BlackTech_TSCookie_elf {
    meta:
        description = "TSCookie ELF version"
        author = "JPCERT/CC Incident Response Group"
        hash = "698643b4c1b11ff227b3c821a0606025aaff390a46638aeb13ed8477c73f28cc"

     strings:
        $command = { 07 AC 00 72 }
        $senddata = { 0? BC 63 72 }
        $config = { C7 ?? ?? ?? 80 00 00 00 89 ?? ?? ?? C7 ?? ?? ?? 78 0B 00 00 }

     condition:
        (#senddata >= 10 and $command) or $config
}

rule BlackTech_IconDown_pe {
    meta:
        description = "detect IconDown"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        hash1 = "634839b452e43f28561188a476af462c301b47bddd0468dd8c4f452ae80ea0af"
        hash2 = "2e789fc5aa1318d0286264d70b2ececa15664689efa4f47c485d84df55231ac4"

    strings:
        $dataheader1 = { 91 00 13 87 33 00 90 06 19 00 }
        $dataheader2 = { C6 [2-3] 91 88 [2-3] C6 [2-3] 13 C6 [2-3] 87 C6 [2-3] 33 88 [2-3] C6 [2-3] 90 C6 [2-3] 06 C6 [2-3] 19 }
        $string1 = "/c %s" ascii
        $string2 = /%s\\[A-X]{1,3}%[l]{0,1}X\.TMP/

    condition:
        (uint16(0) == 0x5A4D) and
        (filesize<5MB) and
        1 of ($dataheader*) and all of ($string*)
}

rule BlackTech_IconDown_resource {
    meta:
        description = "detect IconDown"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f6494698448cdaf6ec0ed7b3555521e75fac5189fa3c89ba7b2ad492188005b4"

    strings:
        $key = {00 13 87 33 00 90 06 19}

    condition:
        (uint16(0) != 0x5A4D) and
        (filesize<5MB) and
        $key
}

rule BlackTech_iam_downloader {
    meta:
        description = "iam downloader malware in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d8500672e293ef4918ff77708c5b82cf34d40c440d5a4b957a5dbd3f3420fdc4"

     strings:
        $fs30 = { 64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 48 08 }
        $com1 = { 81 ?? ?? 58 09 00 00 }
        $com2 = { 81 ?? ?? 5D 09 00 00 }
        $com3 = { 81 ?? ?? 5F 09 00 00 }
        $com4 = { C7 ?? ?? 6E 09 00 00 }
        $send1 = { C7 ?? 6D 09 00 00 }
        $send2 = { C7 ?? ?? 92 5A 76 5D }
        $send3 = { C7 ?? ?? 02 77 00 00 }
        $mutex = "i am mutex!" ascii
        $api1 = { 68 8E 4E 0E EC }
        $api2 = { 68 B0 49 2D DB }
        $api3 = { 68 45 A0 E4 4E }

     condition:
        $fs30 and all of ($com*) or all of ($send*) or ($mutex and all of ($api*))
}

rule BlackTech_HIPO_headercheck {
    meta:
        description = "HIPO_loader malware in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "9cf6825f58f4a4ad261f48f165367040a05af35d2dea27ad8b53b48bf60b09ef"
        hash2 = "abc4b6be1a799e4690a318fe631f28e5c3458c8c0ea30b3f8c9f43ff6b120e1b"

     strings:
        $code1 = { 3D 48 49 50 4F 74 } // HIPO
        $code2 = { 68 22 22 22 22 68 11 11 11 11 56 8B CD E8 } // push 22222222h push 11111111h push esi

     condition:
        all of them
}

rule BlackTech_PLEAD_dummycode {
     meta:
        description = "PLEAD malware dummy code in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d44b38360499cfc6c892b172707e3ea6e72605ad365994ee31cf6a638e288e8d"
        hash2 = "c825c7e575c97bf7280788147bd00dba732e333266f20eb38bce294d9bff238a"

     strings:
        $dummy1 = "test-%d"
        $dummy2 = "test.ini"
        $dummy3 = "ShellClassInfo.txt"
        $dummy4 = "desktop.ini"
        $dummy5 = "%02d%02d%02d"
        $dummy6 = "%s-%02d-%02d-%02d"

     condition:
        4 of ($dummy*)
}

rule BlackTech_Flagprodownloader_str {
     meta:
        description = "Flagpro downloader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "e197c583f57e6c560b576278233e3ab050e38aa9424a5d95b172de66f9cfe970"

     strings:
        $msg1 = "download...." ascii wide
        $msg2 = "download1 finished!" ascii wide
        $msg3 = "download2 finished!" ascii wide
        $msg4 = "start get all pass!" ascii wide
        $msg5 = "start get all pass 1!" ascii wide
        $msg6 = "init Refresh...'" ascii wide
        $msg7 = "busy stop..." ascii wide
        $msg8 = "success!" ascii wide
        $msg9 = "failed!" ascii wide
        $msg10 = "~MYTEMP" ascii wide
        $msg11 = "ExecYes" ascii wide
        $msg12 = "flagpro=" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       6 of them
}

rule BlackTech_Gh0stTimes_str {
     meta:
        description = "Gh0stTimes in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "01581f0b1818db4f2cdd9542fd8d663896dc043efb6a80a92aadfac59ddb7684"

     strings:
        $msg1 = "new big loop connect %s %d ,sleep %d" ascii wide
        $msg2 = "small loop connect %s %d ,sleep %d" ascii wide
        $msg3 = "SockCon1=%d SockCon2=%d" ascii wide
        $msg4 = "connect  %s %d ok" ascii wide
        $msg5 = "connect failure %s %d" ascii wide
        $msg6 = "CFileManager" ascii wide
        $msg7 = "CKernelManager" ascii wide
        $msg8 = "CManager" ascii wide
        $msg9 = "CPortmapManager" ascii wide
        $msg10 = "CShellManager" ascii wide
        $msg11 = "CUltraPortmapManager" ascii wide
        $b1 ={ C6 45 ?? DB C6 45 ?? 50 C6 45 ?? 62 }
            // mov     byte ptr [ebp+var_14], 0DBh ; 'ﾛ'
            // mov     byte ptr [ebp+var_14+1], 50h ; 'P'
            // mov     byte ptr [ebp+var_14+3], 62h ; 'b'
        $b2 = { C6 45 ?? 7B C6 45 ?? 3A C6 45 ?? 79 C6 45 ?? 64 }
            // mov     byte ptr [ebp+var_10], 7Bh ; '{'
            // mov     byte ptr [ebp+var_10+1], 3Ah ; ':'
            // mov     byte ptr [ebp+var_10+2], 79h ; 'y'
            // mov     byte ptr [ebp+var_10+3], 64h ; 'd'
        $b3 = { C6 45 ?? 33 C6 45 ?? F4 C6 45 ?? 27 }
            // mov     byte ptr [ebp+var_C], 33h ; '3'
            // mov     byte ptr [ebp+var_C+1], 0F4h
            // mov     byte ptr [ebp+var_C+2], 27h ; '''
        $b4 = { C6 45 ?? 57 C6 45 ?? EA C6 45 ?? 9F C6 45 ?? 30 }
            // mov     byte ptr [ebp+var_8], 57h ; 'W'
            // mov     byte ptr [ebp+var_8+1], 0EAh
            // mov     byte ptr [ebp+var_8+2], 9Fh
            // mov     byte ptr [ebp+var_8+3], 30h ; '0'

        $pdb = {73 76 63 68 6F 73 74 2D E5 85 A8 E5 8A 9F E8 83 BD 2D E5 8A A0 E5 AF 86 31 32 30 35 5C 52 65 6C 65 61 73 65 5C 73 76 63 68 6F 73 74 2E 70 64 62}
        //$pdb = "svchost-全功能-加密1205\Release\svchost.pdb"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($b*) or $pdb or 5 of ($msg*))
}

rule BlackTech_Gh0stTimes_panel {
     meta:
        description = "Gh0stTimes Panel"
        author = "JPCERT/CC Incident Response Group"
        hash = "18a696b09d0b7e41ad8ab6a05b84a3022f427382290ce58f079dec7b07e86165"

     strings:
        $msg1 = "[server]Listen on %s:%d successful" ascii wide
        $msg2 = "[client] connect to target %s ok" ascii wide
        $msg3 = "WriteFile failure, Close anti-virus software and try again." ascii wide
        $msg4 = "[server<-->client]begin portmap..." ascii wide
        $msg5 = "This folder already contains the file named %s" ascii wide
        $table1 = "CPortMapDlg" ascii wide
        $table2 = "CSettingDlg" ascii wide
        $table3 = "CShellDlg" ascii wide
        $table4 = "CFileManagerDlg" ascii wide
        $table5 = "CFileTransferModeDlg" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       5 of them
}

rule BlackTech_Bifrose_elf {
     meta:
        description = "ELF Bifrose in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "0478fe3022b095927aa630ae9a00447eb024eb862dbfce3eaa3ca6339afec9c1"

     strings:
        $msg1 = { 30 7C 00 31 7C 00 }
        $msg2 = { 35 2E 30 2E 30 2E 30 7C 00 }
        $msg3 = "%c1%s%c3D%c4%u-%.2u-%.2u %.2u:%.2u" ascii
        $msg4 = "%c2%s%c3%u%c4%u-%.2u-%.2u %.2u:%.2u" ascii
        $msg5 = "RecvData 4 bytes header error!" ascii
        $msg6 = "Deal with error! ret==0 goto error!" ascii
        $msg7 = "send data over..." ascii
        $msg8 = "cfgCount=%d" ascii
        $msg9 = "%x : %s %d" ascii
        $msg10 = "recvData timeout :%d" ascii

     condition:
       uint32(0) == 0x464C457F and
       5 of them
}

rule BlackTech_BTSDoor_str {
     meta:
        description = "BTSDoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "85fa7670bb2f4ef3ca688d09edfa6060673926edb3d2d21dff86c664823dd609"
        hash = "ee6ed35568c43fbb5fd510bc863742216bba54146c6ab5f17d9bfd6eacd0f796"

     strings:
        $data1 = "Not implemented!" ascii wide
        $data2 = "Win%d.%d.%d" ascii wide
        $data3 = "CMD Error!" ascii wide
        $data4 = { 76 45 8B 9E 6F 00 00 00 45 76 8B 9E 6F 00 00 00 }
        $pdb1 = "C:\\Users\\Tsai\\Desktop\\20180522windows_tro\\BTSWindows\\Serverx86.pdb" ascii
        $pdb2 = "\\BTSWindows\\Serverx86.pdb" ascii
        $pdb3 = "\\BTSWindows\\Serverx64.pdb" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($pdb*) or 4 of ($data*))
}

rule BlackTech_Hipid_str {
     meta:
        description = "Multi-architecture (ARM or x64) backdoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "3d18bb8b9a5af20ab10441c8cd40feff0aabdd3f4c669ad40111e3aa5e8c54b8"
        hash = "9603b62268c2bbb06da5c99572c3dc2ec988c49c86db2abc391acf53c1cccceb"

     strings:
        $msg1 = "[+] my_dns_query failed." ascii fullword
        $msg2 = "[+] my_dns_query success." ascii fullword
        $msg3 = "[+] connect to %s:%d failed." ascii fullword
        $msg4 = "[+] connect to %s:%d success." ascii fullword
        $msg5 = "cmd: %s" ascii fullword
        $msg6 = "path: %s" ascii fullword
        $msg7 = "has address" ascii fullword
        $msg8 = "host %s" ascii fullword
        $msg9 = {84 D2 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 72 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 77 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 65 (74 ?? |0F ?? ?? ?? 00 00)}
        $func1 = "exec_cmd_send_xor" ascii fullword
        $func2 = "exec_cmd" ascii fullword
        $func3 = "rc4_init" ascii fullword
        $func4 = "my_dns_query" ascii fullword
        $func5 = "rc4_key" ascii fullword
        $func6 = "daemon_init" ascii fullword
        $key1 = "pASSword699" ascii fullword
        $key2 = "345asdflkasduf" ascii fullword

     condition:
       uint32(0) == 0x464C457F and
       (4 of ($msg*) or 4 of ($func*) or 1 of ($key*))
}

rule BlackTech_SelfMakeLoader_str {
     meta:
        description = "SelfMake(SpiderPig) Loader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "2657ca121a3df198635fcc53efb573eb069ff2535dcf3ba899f68430caa2ffce"

     strings:
        $s1 = { 73 65 6C 66 6D 61 6B 65 3? 41 70 70 }
        $s2 = "fixmeconfig"
        $s3 = "[+] config path:%s"
        $cmp_magic_num = { 81 7C ?? ?? (D0 D9 FE E1 | EE D8 FF E0) }

     condition:
       uint16(0) == 0x5A4D and (all of ($s*) or $cmp_magic_num)
}

rule BlackTech_HeavyROTLoader {
     meta:
        description = "HeavyROT Loader in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "F32318060B58EA8CD458358B4BAE1F82E073D1567B9A29E98EB887860CEC563C"

     strings:
        $t1 = { 68 D8 A6 08 00 E8 }
        $t2 = { 43 81 FB 00 97 49 01 }
        $calc_key = { 63 51 E1 B7 8B ?? 8B ?? 81 ?? 00 10 00 00 C1 ?? 10 0B }
        $parse_data = { 8D 6F EE 8B 10 66 8B 70 10 8B 58 04 89 54 24 28 8B 50 08 3B F5 }

     condition:
       all of ($t*) or $calc_key or $parse_data
}

rule BlackTech_SpiderRAT_str {
     meta:
        description = "Spider(SpiderPig) RAT in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "C2B23689CA1C57F7B7B0C2FD95BFEF326D6A22C15089D35D31119B104978038B"

     strings:
        $msg1 = "InternetSetOption m_ProxyUserName Error."
        $msg2 = "InternetSetOption m_ProxyPassWord Error."
        $msg3 = "pWork->HC->HttpSendMessage failed!"
        $msg4 = "Recv_put error!"
        $msg5 = "Send_put error!"
        $msg6 = "Send Success - %d:%d"
        $msg7 = "Recv Success - %d:%d"

     condition:
       uint16(0) == 0x5A4D and 5 of ($msg*) 
}

rule BlackTech_AresPYDoor_str {
     meta:
        description = "AresPYDoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "52550953e6bc748dc4d774fbea66382cc2979580173a7388c01589e8cb882659"

     strings:
        $ares1 = "ares.desktop"
        $ares2 = "~/.ares"
        $ares3 = "grep -v .ares .bashrc >"
        $log1 = "[-]Error! server_hello: status_code=%d"
        $log2 = "[i]runcmd: %s"
        $log3 = "[i]send_output: posting data=%s"
        $log4 = "[i]server_hello: %s"
        $log5 = "[i]starting server_hello"

     condition:
       5 of them
}
