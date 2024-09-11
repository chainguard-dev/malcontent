rule malware_NimFilecoder {
    meta:
      description = "NimCopycatLoader malware in human-operated ransomware attack"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "9a10ead4b8971b830daf1d0b7151462fb6cc379087b65b3013c756db3ce87118"

    strings:
      $str1 = ":wtfbbq" ascii wide
      $lib  = "clr.nim"  ascii wide

    condition:
      uint16(0) == 0x5A4D and all of them
}

rule malware_NimFilecoder02 {
    meta:
      description = "detect NimFilecoder"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "scan, hunt"
      hash1 = "9a10ead4b8971b830daf1d0b7151462fb6cc379087b65b3013c756db3ce87118"
      hash2 = "b6dc9052b9b1c23f90eb214336815e0df1bed8456f8aa5781dd0ec46bff42610"

    strings:
      /*  and    [reg], 55555555h    */
      $Func1 = { 81 E? 55 55 55 55 }
      /*  and    [reg], 0CCCCCCCCh    */
      $Func2 = { 81 E? CC CC CC CC }
      /*  and    [reg], 33333333h  */
      $Func3 = { 81 E? 33 33 33 33 }
      /*  and    [reg], 0F0F0F0Fh   */
      $Func4 = { 81 E? 0F 0F 0F 0F }
      /*  and    [reg], 0F0F0F0F0h   */
      $Func5 = { 81 E? F0 F0 F0 F0 }

      /* stirngs */
      $s0 = "io.nim" fullword ascii
      $s1 = "os.nim" fullword ascii
      $s2 = "fatal.nim" fullword ascii
      $s3 = "GetCommandLineW" fullword ascii
      $s4 = "PathFileExistsW" fullword ascii
      $s5 = "libgcc_s_dw2-1.dll" fullword ascii
      $s6 = "GetModuleFileNameW" fullword ascii
      $s7 = "IsEqualGUID" fullword ascii
      $s8 = "[GC] cannot register thread local variable" fullword ascii
      $s9 = "streams.nim" fullword ascii

    condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3c)) == 0x00004550 and
      all of them
}
