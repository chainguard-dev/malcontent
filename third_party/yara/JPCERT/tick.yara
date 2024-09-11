rule tick_xxmm_parts {
      meta:
        description = "xxmm malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "9374040a9e2f47f7037edaac19f21ff1ef6a999ff98c306504f89a37196074a2"

      strings:
        $pdb1 = "C:\\Users\\123\\Desktop\\xxmm3\\"
        $pdb2 = "C:\\Users\\123\\documents\\visual studio 2010\\Projects\\"
        $pdb3 = "C:\\Users\\123\\Documents\\Visual Studio 2010\\Projects\\"
        $sa = "IsLogAllAccess"
        $sb = "allaccess.log"

      condition:
        ($pdb1 or $pdb2 or $pdb3 or all of ($s*)) and uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550
}

rule tick_xxmm_strings {
      meta:
        description = "detect xxmm in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"

      strings:
        $v1 = "setupParameter:"
        $v2 = "loaderParameter:"
        $v3 = "parameter:"

      condition:
        all of them
}

rule tick_Datper {
      meta:
        description = "detect Datper in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"
        hash = "4d4ad53fd47c2cc7338fab0de5bbba7cf45ee3d1d947a1942a93045317ed7b49"

      strings:
        $a1 = { E8 03 00 00 }
        $b1 = "|||"
        $c1 = "Content-Type: application/x-www-form-urlencoded"
        $delphi = "SOFTWARE\\Borland\\Delphi\\" ascii wide
        $push7530h64 = { C7 C1 30 75 00 00 }
        $push7530h = { 68 30 75 00 00 }

      condition:
        $a1 and $b1 and $c1 and $delphi and ($push7530h64 or $push7530h)
}

rule tick_daserf_mmid {
      meta:
        description = "Daserf malware (Delphi)"
        author = "JPCERT/CC Incident Response Group"
        hash = "94a9a9e14acaac99f7a980d36e57a451fcbce3bb4bf24e41f53d751c062e60e5"

      strings:
        $ua = /Mozilla\/\d.0 \(compatible; MSIE \d{1,2}.0; Windows NT 6.\d; SV1\)/
        $delphi = "Delphi"
        $mmid = "MMID"
        $ccaacmds = "ccaacmds"
        $php = ".php"

      condition:
        $ua and $delphi and #php > 3 and $mmid and $ccaacmds
}

rule tick_daserf_1_5_mini {
    meta:
      description = "Daserf malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "bba61cdb14574c7700d2622167cb06432cd3f97899fa52a0530b83780a6545b2"

  	strings:
    	$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
      $version = "n:1.5"
      $mini = "Mini"

    condition:
    	all of them
}

rule tick_daserf_1_5_not_mini {
    meta:
      description = "Daserf malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "446e71e2b12758b4ceda27ba2233e464932cf9dc96daa758c4b221c8a433570f"

  	strings:
    	$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
      $s1 = "Progman"
      $s3 = ".asp"
      $s4 = "DRIVE_" wide

    condition:
    	all of them
}

rule tick_Gofarer_ua {
    meta:
      description = "Gofarer malware"
      author = "JPCERT/CC Incident Response Group"
      hash = "9a7e18ab6e774a76e3bd74709e9435449915329a1234364b4ef1b0d5d69158db"

	  strings:
        $ua = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.1;+Trident/4.0;+SLCC2;+.NET+CLR+2.0.50727;+.NET4.0E)"

    condition:
        all of them
}

rule tick_xxmm_panel {
    meta:
      description = "xxmm php panel"
      author = "JPCERT/CC Incident Response Group"

	  strings:
        $sa = "REMOTE_ADDR"
        $sb = "HTTP_USER_AGENT"
        $sc = "$clienttype="
        $sd = "$ccmd="
        $se = "ccc_"
        $sf = "sss_"
        $sg = "|||"

    condition:
    	all of them
}

rule tick_SKYSEA_downloader {
      meta:
        description = "Malware downloaded using a vulnerability in SKYSEA"
        author = "JPCERT/CC Incident Response Group"
        hash = "3955d0340ff6e625821de294acef4bdc0cc7b49606a984517cd985d0aac130a3"

  	  strings:
      	$sa = "c:\\Projects\\vs2013\\phc-tools\\Release\\loader.pdb"
        $sb = "%s\\config\\.regeditKey.rc"

      condition:
      	all of them
}

rule tick_Datper_RSAtype {
      meta:
        description = "Datper malware (RSA type)"
        author = "JPCERT/CC Incident Response Group"

      strings:
         $a1 = { E8 03 00 00 }
         $b1 = "|||"
         $c1 = "Content-Type: application/x-www-form-urlencoded"
         $d1 = { A8 03 10 00 FF FF FF FF }
         $push7530h64 = { C7 C1 30 75 00 00 }
         $push7530h = { 68 30 75 00 00 }

      condition:
        $a1 and $b1 and $c1 and $d1 and ($push7530h64 or $push7530h)
}

rule tick_app_js {
      meta:
        description = "JavaScript malware downloaded using a vulnerability in SKYSEA"
        author = "JPCERT/CC Incident Response Group"
        hash = "f36db81d384e3c821b496c8faf35a61446635f38a57d04bde0b3dfd19b674587"

  	  strings:
      	$sa = "File download error!"
        $sb = "/tools/uninstaller.sh"
        $sc = "./npm stop"

      condition:
      	all of them
}

//import "cuckoo"

//rule tick_datper_mutex {
//      meta:
//        description = "Datper malware used mutex strings"
//        author = "JPCERT/CC Incident Response Group"
//        hash1 = "c2e87e5c0ed40806949628ab7d66caaf4be06cab997b78a46f096e53a6f49ffc"
//        hash2 = "4149da63e78c47fd7f2d49d210f9230b94bf7935699a47e26e5d99836b9fdd11"

//      condition:
//        cuckoo.sync.mutex(/d4fy3ykdk2ddssr/) or
//        cuckoo.sync.mutex(/gyusbaihysezhrj/) or
//        cuckoo.sync.mutex(/edc1icnmfgj9UJ\(1G63K/)
//}

rule tick_DALBOTDRPR_strings {
      meta:
        description = "DALBOT dropper malware"
        author = "JPCERT/CC Incident Response Group"

      strings:
        $pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
        $comment = "CreatePipe(cmd) failed!!!"
        $mac = "%.2x%.2x%.2x%.2x%.2x%.2x"
        $aacmd = "AAAAA"

      condition:
        $pdb or ($comment and $mac and $aacmd)
}

rule tick_DALBOT_strings {
      meta:
        description = "DALBOT malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "4092c39282921a8884f5ce3d85fb1f2045323dba2a98332499fdd691fe4b8488"

  	  strings:
        $pdb = "C:\\Users\\jack\\Documents\\Visual Studio 2010\\down_new\\Release\\down_new.pdb"
        $message = "CreatePipe(cmd) failed!!!"
        $url = "&uc=go"

      condition:
        $pdb or ($message and $url)
}

rule tick_ABK_pdb {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "fb0d86dd4ed621b67dced1665b5db576247a10d43b40752c1236be783ac11049"
        hash2 = "3c16a747badd3be70e92d10879eb41d4312158c447e8d462e2b30c3b02992f2a"

      strings:
//		    $pdb1 = "C:\\Users\\Frank\\Desktop\\"
//        $pdb2 = "C:\\Users\\Frank\\Documents\\"
        $pdb3 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\Hidder.pdb"
        $pdb4 = "C:\\Users\\Frank\\Documents\\Visual Studio 2010\\Projects\\avenger\\Release\\avenger.pdb"
        $pdb5 = "C:\\Users\\Frank\\Desktop\\ABK\\Release\\ABK.pdb"

      condition:
//        ($pdb1 or $pdb2 or $pdb3 or $pdb4 or $pdb5) and uint16(0) == 0x5A4D
        ($pdb3 or $pdb4 or $pdb5) and uint16(0) == 0x5A4D
}

rule tick_ABK_downloader {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash = "5ae244a012951ab2089ad7dc70e564f90586c78ff08b93bb2861bb69edcdd5c5"

      strings:
        $a1 = "PccNT.exe" wide
        $bytecode = {	50 63 63 00 4e 54 2e 00 65 78 65 00 }

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize>10MB) and
        ((any of ($a1)) or $bytecode)
}

rule tick_ABK_downloader_susp_ua {
      meta:
        description = "ABK downloader malware"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "ade2a4c4fc0bd291d2ecb2f6310c75243107301f445a947409b38777ff014972"
        hash2 = "32dbfc069a6871b2f6cc54484c86b21e2f13956e3666d08077afa97d410185d2"
        hash3 = "d1307937bd2397d92bb200b29eeaace562b10474ff19f0013335e37a80265be6"

      strings:
        $UA= "Mozilla/4.0(compatible;MSIE8.0;WindowsNT6.0;Trident/4.0)"

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize<50MB) and
        $UA
}

//rule tick_ABK_downloader_susp_mutex {
//      meta:
//        description = "ABK downloader malware"
//        author = "JPCERT/CC Incident Response Group"
//        hash1 = "ade2a4c4fc0bd291d2ecb2f6310c75243107301f445a947409b38777ff014972"
//        hash2 = "32dbfc069a6871b2f6cc54484c86b21e2f13956e3666d08077afa97d410185d2"
//        hash3 = "d1307937bd2397d92bb200b29eeaace562b10474ff19f0013335e37a80265be6"

//      condition:
//        (uint16(0) == 0x5A4D) and
//        (filesize<50MB) and
//        (cuckoo.sync.mutex(/PPGword/) or cuckoo.sync.mutex(/CQFB/))
//}

rule malware_gokcpdoor_golang {
    meta:
        description = "gokcpdoor"
        author = "JPCERT/CC Incident Response Group"
        hash = "2dd8ab1493a97e0a4416e077d6ce1c35c7b2d8749592b319a7e2a8f4cd1cc008"

     strings:
        $gofunc1 = "CopyConn2StdinPipe" ascii wide
        $gofunc2 = "CopyStdoutPipe2Conn" ascii wide
        $gofunc3 = "handleConnection" ascii wide
        $gofunc4 = "addudpforward" ascii wide
        $gofunc5 = "addtcpforward" ascii wide
        $gofunc6 = "addsocks5" ascii wide
        $gofunc7 = "handleConnWait" ascii wide
        $gofunc8 = "readconfig" ascii wide
        $log1 = "[+] socks5 add ok" ascii wide
        $log2 = "[+] portforward add ok" ascii wide
        $log3 = "[-] First param must be one of [add,del,list]" ascii wide
        $log4 = "[-] socks5 del param num must exceed 3!" ascii wide
        $log5 = "[*] portforward list:" ascii wide
        $log6 = "[*] please input a supported command, you can see help first!" ascii wide
        $str1 = "!!!ok!!!"
        $str2 = {23 23 23 64 6F 77 6E 6C} // ###downloadend$$$
        $str3 = {23 23 23 75 70 6C 6F 61} // ###uploadend$$$
        $gofile1 = "kcp.go" ascii wide
        $gofile2 = "udp.go" ascii wide
        $gofile3 = "target.go" ascii wide
        $gofile4 = "exec_lin.go" ascii wide
        $gofile5 = "gokcpdoor[0-9]" ascii wide

     condition:
        6 of ($gofunc*) or 5 of ($log*) or all of ($str*) or all of ($gofile*)
}
