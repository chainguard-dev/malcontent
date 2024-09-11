rule malware_QakBot {
    meta:
      description = "detect QakBot(a.k.a. Qbot, Quakbot, Pinkslipbot) in memory"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "memory scan"
      hash1 = "d766cd76c93dcc47d0d02e073216d792d1b377e31a4bae74969ab8076e286db3"
      hash2 = "717298e663d574444b63bb152063795326ac7c04edc9873a4ac2e407e1f550a1"

    strings:
      $cryptFunc1 = { 33 D2 6A ?? 5B F7 F3 }  /* xor edx, edx; push 5Ah; pop ebx; div ebx */
      $cryptFunc2 = { 32 04 37 } /* xor al, [edi+esi] */
      /*  .rdata:1001B258 dd 0, 1DB71064h, 3B6E20C8h, 26D930ACh
          .rdata:1001B258 dd 76DC4190h, 6B6B51F4h, 4DB26158h, 5005713Ch   */
      $hashFunc = { 64 10 B7 1D C8 20 6E 3B AC 30 D9 26  90 41 DC 76 F4 51 6B 6B}

    condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3c)) == 0x00004550 and 
      $cryptFunc1 and $cryptFunc2 and
      $hashFunc
}