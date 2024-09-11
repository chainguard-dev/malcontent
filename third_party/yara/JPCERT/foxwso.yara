rule webshell_FoxWSO_str {
     meta:
        description = "Webshell FoxWSO"
        author = "JPCERT/CC Incident Response Group"
        hash = "5ab2258d38805007226166f946bcc2794310bd9889f03fcb1894f2061716b0f9"

     strings:
        $str1 = "tjwlltii akhmhcij"
        $str2 = "!defined('lmhelqpg')"
        $str3 = { 69 66 28 21 66 75 6e 63 74 69 6f 6e 5f 65 78 69 73 74 73 28 22 94 e3 d7 a9 a7 9a e0 c5 f3 f6 22 29 }

     condition:
        uint32(0) == 0x68703F3C and 1 of ($str*)
}
