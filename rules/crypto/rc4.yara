rule rc4_ksa: low {
  meta:
    author      = "Thomas Barabosch"
    description = "RC4 key scheduling algorithm"

  strings:
    // false-positive: $cmp_eax_256 = { 3d 00 01 00 00 }  // cmp eax, 256
    $cmp_e_x_256 = { 81 f? 00 01 00 00 }  // cmp {ebx, ecx, edx}, 256
    // false-positive: $cmp_rax_256 = { 48 3d 00 01 00 00 }  // cmp rax, 256
    $cmp_r_x_256 = { 48 81 f? 00 01 00 00 }  // cmp {rbx, rcx, …}, 256

  condition:
    filesize < 10MB and any of them
}

rule rc4_constants: medium {
  meta:
    descrption = "Identify constants used by the ARC4 cryptographic algorithm."
    author     = "@shellcromancer <root@shellcromancer.io>"
    version    = "0.1"
    date       = "2022-01-03"
    reference  = "https://www.goggleheadedhacker.com/blog/post/reversing-crypto-functions#identifying-rc4-in-assembly"
    reference  = "https://0xc0decafe.com/detect-rc4-encryption-in-malicious-binaries/"
    reference  = "https://blog.talosintelligence.com/2014/06/an-introduction-to-recognizing-and.html"

  strings:
    $opt0  = { 03 02 01 00 }
    $opt1  = "\x07\x06\x05\x04"
    $opt2  = "\x0B\x0A\x09\x08"
    $opt3  = "\x0F\x0E\x0D\x0C"
    $opt4  = "\x13\x12\x11\x10"
    $opt5  = "\x17\x16\x15\x14"
    $opt6  = "\x1B\x1A\x19\x18"
    $opt7  = "\x1F\x1E\x1D\x1C"
    $opt8  = "#\"! "
    $opt9  = "'&%$"
    $opt10 = "+*)("
    $opt11 = "/.-,"
    $opt12 = "3210"
    $opt13 = "7654"
    $opt14 = ";:98"
    $opt15 = "?>=<"
    $opt16 = "CBA@"
    $opt17 = "GFED"
    $opt18 = "KJIH"
    $opt19 = "ONML"
    $opt20 = "SRQP"
    $opt21 = "WVUT"
    $opt22 = "[ZYX"
    $opt23 = "_^]\\"
    $opt24 = "gfed"
    $opt25 = "kjih"
    $opt26 = "onml"
    $opt27 = "srqp"
    $opt28 = "wvut"
    $opt29 = "{zyx"
    $opt30 = "\x7F\x7E\x7D\x7C"
    $opt31 = { 83 82 81 80 }
    $opt32 = { 87 86 85 84 }
    $opt33 = { 8B 8A 89 88 }
    $opt34 = { 8F 8E 8D 8C }
    $opt35 = { 93 92 91 90 }
    $opt36 = { 97 96 95 94 }
    $opt37 = { 9B 9A 99 98 }
    $opt38 = { 9F 9E 9D 9C }
    $opt39 = { A3 A2 A1 A0 }
    $opt40 = { A7 A6 A5 A4 }
    $opt41 = { AB AA A9 A8 }
    $opt42 = { AF AE AD AC }
    $opt43 = { B3 B2 B1 B0 }
    $opt44 = { B7 B6 B5 B4 }
    $opt45 = { BB BA B9 B8 }
    $opt46 = { BF BE BD BC }
    $opt47 = { C3 C2 C1 C0 }
    $opt48 = { C7 C6 C5 C4 }
    $opt49 = { CB CA C9 C8 }
    $opt50 = { CF CE CD CC }
    $opt51 = { D3 D2 D1 D0 }
    $opt52 = { D7 D6 D5 D4 }
    $opt53 = { DB DA D9 D8 }
    $opt54 = { DF DE DD DC }
    $opt55 = { E3 E2 E1 E0 }
    $opt56 = { E7 E6 E5 E4 }
    $opt57 = { EB EA E9 E8 }
    $opt58 = { EF EE ED EC }
    $opt59 = { F3 F2 F1 F0 }
    $opt60 = { F7 F6 F5 F4 }
    $opt61 = { FB FA F9 F8 }
    $opt62 = { FF FE FD FC }
    $opt63 = "cba`"

  condition:
    75 % of ($opt*)
}
