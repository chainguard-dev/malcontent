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
    $opt1  = { 07 06 05 04 }
    $opt2  = { 0B 0A 09 08 }
    $opt3  = { 0F 0E 0D 0C }
    $opt4  = { 13 12 11 10 }
    $opt5  = { 17 16 15 14 }
    $opt6  = { 1B 1A 19 18 }
    $opt7  = { 1F 1E 1D 1C }
    $opt8  = { 23 22 21 20 }
    $opt9  = { 27 26 25 24 }
    $opt10 = { 2B 2A 29 28 }
    $opt11 = { 2F 2E 2D 2C }
    $opt12 = { 33 32 31 30 }
    $opt13 = { 37 36 35 34 }
    $opt14 = { 3B 3A 39 38 }
    $opt15 = { 3F 3E 3D 3C }
    $opt16 = { 43 42 41 40 }
    $opt17 = { 47 46 45 44 }
    $opt18 = { 4B 4A 49 48 }
    $opt19 = { 4F 4E 4D 4C }
    $opt20 = { 53 52 51 50 }
    $opt21 = { 57 56 55 54 }
    $opt22 = { 5B 5A 59 58 }
    $opt23 = { 5F 5E 5D 5C }
    $opt24 = { 67 66 65 64 }
    $opt25 = { 6B 6A 69 68 }
    $opt26 = { 6F 6E 6D 6C }
    $opt27 = { 73 72 71 70 }
    $opt28 = { 77 76 75 74 }
    $opt29 = { 7B 7A 79 78 }
    $opt30 = { 7F 7E 7D 7C }
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
    $opt63 = { 63 62 61 60 }

  condition:
    75 % of ($opt*)
}
