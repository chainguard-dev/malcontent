rule malware_BRC4_code {
     meta:
        description = "Brute Ratel C4"
        author = "JPCERT/CC Incident Response Group"
        hash = "54e844b5ae4a056ca8df4ca7299249c4910374d64261c83ac55e5fdf1b59f01d"
        hash = "31acf37d180ab9afbcf6a4ec5d29c3e19c947641a2d9ce3ce56d71c1f576c069"
        hash = "973f573cab683636d9a70b8891263f59e2f02201ffb4dd2e9d7ecbb1521da03e"

     strings:
        $func1 = { 41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC A8 00 00 00 E8 }
        $func2 = { 50 68 ?? ?? 00 00 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 }
        $func3 = { 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 00 00 00 00 50 B8 (02|01) 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       filesize<500KB and
       ($func1 or #func2 > 2 or #func3 > 2)
}