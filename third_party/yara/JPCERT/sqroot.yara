rule malware_sqroot_code {
     meta:
        description = "sqroot malware using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "556018653737386c9d291cb2ca90cde360394897b2e7800c7eb119730d3bda3c"

     strings:
        $str1 = "sqroot" ascii wide
        $str2 = "1234QWER11" ascii wide
        $str3 = "edge_service_packet.tmp" ascii wide
        $str4 = "/ol" ascii wide
        $str5 = "/task" ascii wide
        $str6 = "%s %s \"%s-%s|%s-%s %s,%s,%s|%s-%s -%s|%s-%s -%s %d" ascii wide
        $str7 = "jss/font-awesome.min.css" ascii wide
        $str8 = "css/jquery-ui.min.css" ascii wide
        $str9 = "{\"%s\":\"%s(%s)\",\"%s\":\"%s\",\"%s\":\"%s\"}" ascii wide
        $str10 = "/dl" ascii wide
        $str11 = "21.30.ec.9d.c4.20" ascii wide
        $str12 = "/papers/ja-jp" ascii wide
        $filename1 = "8015ba282c" ascii wide
        $filename2 = "abb8fcc3b5" ascii wide
        $filename3 = "8714c42184" ascii wide
        $filename4 = "6eadde753d" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (7 of ($str*) or all of ($filename*))
}

//import "pe"
//rule malware_sqroot_loader {
//     meta:
//        description = "sqroot loader using unknown actors"
//        author = "JPCERT/CC Incident Response Group"
//        hash = "e65f5683ad6272feff5a59175ef55525e0c873c373cf030fd937e2527f53efd1"

//     condition:
//       uint16(0) == 0x5A4D and
//       uint32(uint32(0x3c)) == 0x00004550 and
//       pe.number_of_sections >= 6 and
//       for any i in (0..pe.number_of_sections -1):
//       (
//           pe.sections[i].name iequals ".newimp"
//       ) and
//       (
//           pe.imports("dmiapi32.dll", "R32Start")
//       )
//}

rule malware_sqroot_lnk {
     meta:
        description = "sqroot drop lnk file using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "16ac092af64bbab7dbaef60cd796e47c5d2a6fec6164906c1fbd0c9c51861936"

     strings:
       $command1 = "bwBuACAAZQByAHIAbwByACAAcgBlAHMA" wide
       $command2 = "%temp%\\ex.lnk" wide nocase
       $command3 = "%temp%\\f.vbs" wide nocase
       $command4 = "%temp%\\b64.txt" wide nocase
       $command5 = "%temp%\\i.log" wide nocase
       $command6 = "%temp%\\result.vbs" wide nocase
       $command7 = ".position = .size-12" wide
       $command8 = "AscW(.read(2))=^&" wide

     condition:
       uint16(0) == 0x004c and
       filesize>1MB and
       4 of ($command*)
}

rule malware_sqroot_webphp {
     meta:
        description = "sqroot drop web page using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "8b9f229012512b9e4fb924434caa054275410574c5b0c364b850bb2ef70a0f3d"

     strings:
       $func1 = "send_download_file_as_exe($filename)" ascii
       $func2 = "check_remote_client()" ascii
       $func3 = "mylog('[e]');" ascii
       $func4 = "mylog('[z]');" ascii
       $func5 = "mylog('[4]');" ascii
       $func6 = "mylog('[*]');" ascii
       $func7 = "mylog('[p]');" ascii
       $func8 = "mylog($flag)" ascii
       $func9 = "get_remote_ip()" ascii

     condition:
       uint32(0) == 0x68703f3c and
       4 of ($func*)
}

rule malware_sqroot_cat {
   meta:
     description = "cat plugin downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $s1 = "Catcher start" wide
     $s2 = "Catcher exit" wide
     $s3 = "[%04d/%02d/%02d %02d:%02d:%02d] %s\n" wide
     $s4 = {2A 00 6C 00 6F 00 67 00  00 00 00 00 23 00 21 00}

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     3 of them
}

rule malware_sqroot_snapshot {
   meta:
     description = "snapshot plugin downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $s1 = "e:\\vsprojects\\crataegus\\snaptik\\maz\\miniz.c" wide
     $s2 = "%s-%02d%02d_%02d%02d%02d.maz" wide
     $s3 = "%s%s_%02d%02d%02d(%d).png" wide
     $s4 = "gdi_cache" wide
     $s5 = "capture_flag.ini" wide
     $s6 = "cf_mptmb" wide
     $s7 = "cf_pakdir" wide
     $s8 = "DoGdiCapture" ascii

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     4 of them
}

rule malware_sqroot_keylogger {
   meta:
     description = "keylog plugin downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $s1 = "record-%04d%02d%02d-%02d%02d%02d.ini" ascii
     $s2 = "g_hKeyLogMsgLoopThread exit" ascii
     $s3 = "OCR_INI_DEBUG.abc" ascii
     $s4 = {59 6F 75 27 72 65 20 61  63 74 69 76 61 74 65 64 00 00 00 00 52 33 32 41 63 74 69 76 65}

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     2 of them
}

rule malware_sqroot_pluginloader {
   meta:
     description = "plugin loader downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $a1 = "Active() found" ascii
     $a2 = "Active:Thread created!" ascii
     $b1 = {6A 74 70 61 00}
     $b2 = {6A 74 70 63 00}
     $b3 = {6A 74 70 74 00}
     $b4 = "%s*.tmp" ascii
     $c1 = "SignalS1" ascii
     $c2 = "SignalS2" ascii
     $c3 = "SignalS3" ascii

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     5 of them
}

rule malware_sqroot_coreloader {
   meta:
     description = "loader downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $query = "%s?hid=%s&uid=%s&cid=%x" ascii
     $decode_routine = {8A 8A ?? ?? ?? ?? 02 C1 32 C1 2A C1 0F B6 8E ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 8D 46 ?? 99 F7 FF 8A 82 ?? ?? ?? ?? 02 C8 32 C8 2A C8 88 8E ?? ?? ?? ?? 83 C6 02 81 FE 0A 04 00 00}

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     all of them
}

rule malware_sqroot_corerat {
   meta:
     description = "RAT downloaded by sqroot"
     author = "JPCERT/CC Incident Response Group"

   strings:
     $a1 = "openfile %s error!" ascii
     $a2 = "remote file error!" ascii
     $a3 = "upload well!" ascii
     $a4 = "%s?hid=%s&uid=%s&cid=%x" ascii
     $a5 = "%s|%s|%s|%s|%s|%s|%d|%s|" ascii
     $b1 = {68 24 11 00 00 E8}
     $b2 = {C7 03 37 11 00 00}

   condition:
     uint16(0) == 0x5A4D and
     uint32(uint32(0x3c)) == 0x00004550 and
     (all of ($a*) or all of ($b*))
}

