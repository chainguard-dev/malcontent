
rule malware_vboxuserRAT {
    meta:
      description = "Hunt vboxuserRAT"
      author = "JPCERT/CC Incident Response Group"
      hash = "47FB80593A1924AE4351C3A8C9EE9F1F365267719531387E88A4A82000088E48"

    strings:
      /* cmds function
      .text:000000038D0BB00A 48 BA 65 78 65 5F 64 6C 6C 5F        mov     rdx, 5F6C6C645F657865h
      .text:000000038D0BB014 48 39 10                             cmp     [rax], rdx
      .text:000000038D0BB017 0F 85 07 03 00 00                    jnz     loc_38D0BB324
      .text:000000038D0BB01D 48 BA 72 75 6E 64 6C 6C 33 32        mov     rdx, 32336C6C646E7572h
      .text:000000038D0BB027 48 39 50 08                          cmp     [rax+8], rdx
      .text:000000038D0BB02B 0F 85 F3 02 00 00                    jnz     loc_38D0BB32
      */
      $cmdfunc1 = { 65 78 65 5F 64 6C 6C 5F }
      $cmdfunc2 = { 72 75 6E 64 6C 6C 33 32 }

      /* cmds function
      .text:000000038D0BAC94 48 BA 73 68 65 6C 6C 5F 63 6C        mov     rdx, 6C635F6C6C656873h
      .text:000000038D0BAC9E 66 90                                xchg    ax, ax
      .text:000000038D0BACA0 48 39 10                             cmp     [rax], rdx
      .text:000000038D0BACA3 75 61                                jnz     short loc_38D0BAD06
      .text:000000038D0BACA5 81 78 08 61 73 73 69                 cmp     dword ptr [rax+8], 69737361h
      */
      $cmdfunc3 = { 73 68 65 6C 6C 5F 63 6C }

      /* cmds function
      .text:000000038D0BAE43 48 BA 72 75 6E 5F 77 69 74 68        mov     rdx, 687469775F6E7572h
      .text:000000038D0BAE4D 48 39 10                             cmp     [rax], rdx
      */
      $cmdfunc4 = { 72 75 6E 5F 77 69 74 68 }

      /* cmds function
      .text:000000038D0BAD06 48 BA 73 68 65 6C 6C 5F 73 79        mov     rdx, 79735F6C6C656873h
      .text:000000038D0BAD10 48 39 10                             cmp     [rax], rdx
      */
      $cmdfunc5 = { 73 68 65 6C 6C 5F 73 79 }

      $cmdstr1 = "run_dll_from_memory" ascii
      $cmdstr2 = "run_exe_from_memory" ascii

    condition:
      (uint16(0) == 0x5A4D) and
      (uint32(uint32(0x3c)) == 0x00004550) and
      (filesize > 3MB) and
      (filesize < 10MB) and
      (3 of ($cmdfunc*)) and
      (1 of ($cmdstr*))
}
