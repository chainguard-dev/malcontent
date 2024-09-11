
rule malware_Pangolin8RAT {
    meta:
        description = "Hunt GobLoaderScript"
        author = "JPCERT/CC Incident Response Group"
        hash = "F95441B1CD6399887E99DBE6AA0CEB0CA907E8175192E71F8F1A4CCA49E8FC82"
    
    strings:
        /* Function Address: 0x7ff6887e5bf0 : wrap_get_filesize
        57                                  push    rdi                   
        41 56                               push    r14                   
        41 57                               push    r15                   
        48 83 EC 20                         sub     rsp, 20h              
        49 C7 C0 FF FF FF FF                mov     r8, 0FFFFFFFFFFFFFFFFh
        4C 8B FA                            mov     r15, rdx              
        49 8B D8                            mov     rbx, r8               
        48 8B F9                            mov     rdi, rcx              
        66 90                               xchg    ax, ax                
        48 FF C3                            inc     rbx                   
        */
        $func0 = { 57 41 56 41 57 48 83 EC 20 49 C7 C0 FF FF FF FF 4C 8B FA 49 8B D8 48 8B F9 66 90 48 FF C3 }

        /* Function Address: 0x7ff6887e6380 : concat_strings
        48 BB FE FF FF FF FF FF FF 7F       mov     rbx, 7FFFFFFFFFFFFFFEh
        48 8B C3                            mov     rax, rbx              
        4D 8B E9                            mov     r13, r9               
        49 2B C6                            sub     rax, r14              
        48 8B F1                            mov     rsi, rcx              
        48 3B C2                            cmp     rax, rdx              
        */
        $func1 = { 48 BB FE FF FF FF FF FF FF 7F 48 8B C3 4D 8B E9 49 2B C6 48 8B F1 48 3B C2 }

        /* Function Address: 0x7FF6887E50AB2
        .text:00007FF6887E507B 48 8D 45 B0                 lea     rax, [rbp+880h+slash_t]
        .text:00007FF6887E507F 48 89 44 24 48              mov     [rsp+980h+var_938], rax
        .text:00007FF6887E5084 48 89 5D C0                 mov     [rbp+880h+var_8C0], rbx
        .text:00007FF6887E5088 48 C7 45 C8 07 00 00 00     mov     [rbp+880h+var_8B8], 7
        .text:00007FF6887E5090 66 89 5D B0                 mov     word ptr [rbp+880h+slash_t], bx
        .text:00007FF6887E5094 41 B8 01 00 00 00           mov     r8d, 1
        .text:00007FF6887E509A 48 8D 15 03 0B 08 00        lea     rdx, asc_7FF688865BA4 ; "/"
        .text:00007FF6887E50A1 48 8D 4D B0                 lea     rcx, [rbp+880h+slash_t]
        .text:00007FF6887E50A5 E8 B6 09 00 00              call    strcpy_w_maybe
        .text:00007FF6887E50AA 90                          nop

        .text:0000000140004781 48 8D 45 98                 lea     rax, [rbp+8B0h+var_918]
        .text:0000000140004785 48 89 85 C0 08 00 00        mov     [rbp+8B0h+arg_0], rax
        .text:000000014000478C 48 89 5D A8                 mov     [rbp+8B0h+var_908], rbx
        .text:0000000140004790 48 C7 45 B0 07 00 00 00     mov     [rbp+8B0h+var_900], 7
        .text:0000000140004798 66 89 5D 98                 mov     [rbp+8B0h+var_918], bx
        .text:000000014000479C 41 B8 01 00 00 00           mov     r8d, 1
        .text:00000001400047A2 48 8D 15 A3 47 08 00        lea     rdx, asc_140088F4C ; "/"
        .text:00000001400047A9 48 8D 4D 98                 lea     rcx, [rbp+8B0h+var_918]
        .text:00000001400047AD E8 7E 12 00 00              call    sub_140005A30
        .text:00000001400047B2 90                          nop                                      nop
        */
		$func2 = { 48 89 5D ?? 48 C7 45 ?? 07 00 00 00 66 89 5D ?? 41 B8 01 00 00 00 48 8D 15 ?? ?? 08 00 48 8D 4D ?? E8 ?? ?? ?? ?? 90 }
		
        /* .text:00007FF6887E1700 set_same_filetime_from_ntd_dlll
		.text:00007FF6887E1729 41 B8 08 02 00 00           mov     r8d, 208h
        .text:00007FF6887E172F E8 4C A1 03 00              call    do_memset
        .text:00007FF6887E1734 BA 04 01 00 00              mov     edx, 104h       ; uSize
        .text:00007FF6887E1739 48 8D 4C 24 60              lea     rcx, [rsp+288h+Buffer] ; lpBuffer
        .text:00007FF6887E173E FF 15 54 DF 06 00           call    cs:GetSystemDirectoryW
        .text:00007FF6887E1744 4C 8D 05 FD 3E 08 00        lea     r8, aNtdllDll_0 ; "\\ntdll.dll"
        .text:00007FF6887E174B BA 04 01 00 00              mov     edx, 104h       ; SizeInWords
        .text:00007FF6887E1750 48 8D 4C 24 60              lea     rcx, [rsp+288h+Buffer] ; Destination
        .text:00007FF6887E1755 E8 32 EA 03 00              call    wcscat_s
        .text:00007FF6887E175A 48 8D 4C 24 60              lea     rcx, [rsp+288h+Buffer] ; lpFileName
        .text:00007FF6887E175F FF 15 2B DF 06 00           call    cs:GetFileAttributesW
        .text:00007FF6887E1765 8B D0                       mov     edx, eax        ; dwFileAttributes
        .text:00007FF6887E1767 48 8B CF                    mov     rcx, rdi        ; lpFileName
        .text:00007FF6887E176A FF 15 18 DF 06 00           call    cs:SetFileAttributesW
        .text:00007FF6887E1770 45 33 C9                    xor     r9d, r9d        ; lpSecurityAttributes
        .text:00007FF6887E1773 48 C7 44 24 30 00 00 00 00  mov     [rsp+288h+hTemplateFile], 0 ; hTemplateFile
        .text:00007FF6887E177C C7 44 24 28 80 00 00 00     mov     [rsp+288h+dwFlagsAndAttributes], 80h ; dwFlagsAndAttributes
        .text:00007FF6887E1784 48 8D 4C 24 60              lea     rcx, [rsp+288h+Buffer] ; lpFileName
        .text:00007FF6887E1789 BA 00 00 00 80              mov     edx, 80000000h  ; dwDesiredAccess
        .text:00007FF6887E178E C7 44 24 20 03 00 00 00     mov     [rsp+288h+dwCreationDisposition], 3 ; dwCreationDisposition
        .text:00007FF6887E1796 45 8D 41 01                 lea     r8d, [r9+1]     ; dwShareMode
        .text:00007FF6887E179A FF 15 60 DF 06 00           call    cs:CreateFileW
        .text:00007FF6887E17A0 48 8B D8                    mov     rbx, rax
        .text:00007FF6887E17A3 48 85 C0                    test    rax, rax
        */
		$func3 = { 41 B8 08 02 00 00 E8 ?? ?? 03 00 BA 04 01 00 00 48 8D 4C 24 ?? FF 15 ?? ?? ?? 00 4C 8D 05 ?? ?? 08 00 BA 04 01 00 00 48 8D 4C 24 ?? E8 ?? EA 03 00 48 8D 4C 24 ?? FF 15 ?? ?? ?? 00 8B D0 48 8B CF FF 15 ?? ?? ?? 00 45 33 C9 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 48 8D 4C 24 ?? BA 00 00 00 80 C7 44 24 20 03 00 00 00 45 8D 41 01 FF 15 ?? ?? ?? 00 48 8B D8 48 85 C0 }

		/* strings */
        $str01 = "smcache.dat" ascii wide
        $str04 = "file:///" ascii wide

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize < 2MB)	
        and ( ( 3 of ($func*) )
		    or ( 2 of ($str*) ) )
}
