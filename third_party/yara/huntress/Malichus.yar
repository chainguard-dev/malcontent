/*
   YARA Rule Set
   Author: Jai Minton, Alden Schmidt - Huntress
   Date: 2024-12-11
   Identifier: Malichus
   Reference: https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis
*/

/* Rule Set ----------------------------------------------------------------- */

rule Malichus_SFile {
   meta:
      description = "Malichus - file SFile.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "57ec6d8891c95a259636380f7d8b8f4f8ac209bc245d602bfa9014a4efd2c740"
      id = "93f23528-cd17-4606-93a8-395e8d94b911"
   strings:
      $s1 = "FAILED: File not exists or not readable" fullword ascii
      $s2 = "SFile.java" fullword ascii
      $s3 = "svdSize" fullword ascii
      $s4 = "fStop" fullword ascii
      $s5 = "FileOutputStream;" fullword ascii
      $s6 = "good" fullword ascii
      $s7 = "FileInputStream;" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      4 of them
}

rule Malichus_Proc {
   meta:
      description = "Malichus - file Proc.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "1ba95af21bac45db43ebf02f87ecedde802c7de4d472f33e74ee0a5b5015a726"
      id = "ca6746b8-1b9f-46e5-9ffb-138414e7a26d"
   strings:
      $s1 = "chid" fullword ascii
      $s2 = "fStop" fullword ascii
      $s3 = "Timeout getting pipe-data" fullword ascii
      $s4 = "Ftprootpath" fullword ascii
      $s5 = "getTextContent" fullword ascii
      $s6 = "hostfile" fullword ascii
      $s7 = "getErrorStream" fullword ascii
      $s8 = "exec 2>&1" fullword ascii
      $s9 = "%username%" fullword ascii
      $s10 = "pipeDataLen=" fullword ascii
      $s11 = "ishell" fullword ascii
      $s12 = "pipeBuf" fullword ascii
      $s13 = "pipeDataLen" fullword ascii
      $s14 = "getNodeVal" fullword ascii
      $s15 = "loadOptions" fullword ascii
      $s16 = "confParser" fullword ascii
      $s18 = "readable" fullword ascii
      $s19 = "Rest cmd=" fullword ascii
      $s20 = "getAttr" fullword ascii
      $s21 = "prs-conf" fullword ascii
      $s22 = "conf/Top.xml" ascii
      $s23 = "conf/Options.xml" ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      8 of them
}

rule Malichus_Slot {
   meta:
      description = "Malichus - file Slot.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "1e351bb7f6e105a3eaa1a0840140ae397e0e79c2bdc69d5e1197393fbeefc29b"
      id = "02908c30-6ba9-4d71-9f06-b876a2b0ebcd"
   strings:
      $s1 = "Slot.java" fullword ascii
      $s2 = "channel" fullword ascii
      $s3 = "connect" fullword ascii
      $s4 = "interestOps" fullword ascii
      $s5 = "evWrite" fullword ascii
      $s6 = "evConnect" fullword ascii
      $s7 = "evRead" fullword ascii
      $s8 = "chid" fullword ascii
      $s9 = "fStop" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      5 of them
}

rule Malichus_DwnLevel {
   meta:
      description = "Malichus - file DwnLevel.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "f80634ce187ad4834d8f68ac7c93500d9da69ee0a7c964df1ffc8db1b6fff5a9"
      id = "450bc40c-9e0d-4c00-a000-c612a78de1cb"
   strings:
      $s1 = "DwnLevel.java" fullword ascii
      $s2 = "DwnLevel" fullword ascii
      $s3 = "files" fullword ascii
      $s4 = "state" fullword ascii
      $s5 = "LineNumberTable" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      all of them
}

rule Malichus_Dwn {
   meta:
      description = "Malichus - file Dwn.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "429d24e3f30c7e999033c91f32b108db48d669fde1c3fa62eff9da2697ed078e"
      id = "5a59f469-e61e-4088-ad46-060e66a56fb0"
   strings:
      $s1 = "getCurrZipSize" fullword ascii
      $s2 = "listFiles" fullword ascii
      $s3 = "Signature" fullword ascii
      $s4 = "remove" fullword ascii
      $s5 = "SrvSlot" fullword ascii
      $s6 = "DwnLevel" fullword ascii
      $s7 = "currZipSize" fullword ascii
      $s8 = "putNextEntry" fullword ascii
      $s9 = "addFile ex=" fullword ascii
      $s10 = "Dwn.java" fullword ascii
      $s11 = "tmLastStatSend" fullword ascii
      $s12 = "rdbuf" fullword ascii
      $s13 = "zipNum" fullword ascii
      $s14 = "PK_DWN" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      8 of them
}

rule Malichus_Cli {
   meta:
      description = "Malichus - file Cli.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "6499e67082b9f1b5553b0f561d2c359b452ca16eb98582904c9f1aa70ebb9d07"
      id = "3f3b4d97-5a30-46dc-b339-d01b2330cdec"
   strings:
      $s1 = "+powershell -Noninteractive -EncodedCommand " fullword ascii
      $s2 = "getHostName" fullword ascii
      $s3 = "getLocalHost" fullword ascii
      $s4 = "sleep 3;rm -f '" fullword ascii
      $s5 = "runDelFileCmd" fullword ascii
      $s6 = "getEncoder" fullword ascii
      $s7 = "selectedKeys" fullword ascii
      $s8 = "getCanonicalFile" fullword ascii
      $s9 = "hostname" fullword ascii
      $s10 = "connect" fullword ascii
      $s11 = "remove" fullword ascii
      $s12 = "SrvSlot" fullword ascii
      $s13 = "fIsWin" fullword ascii
      $s14 = "cliid" fullword ascii
      $s15 = "Cli.java" fullword ascii
      $s16 = "fStop" fullword ascii
      $s17 = "os.name" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      10 of them
}

rule Malichus_SrvSlot {
   meta:
      description = "Malichus - file SrvSlot.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "f4e5a6027b25ede93b10e132d5f861ed7cca1df7e36402978936019930e52a16"
      id = "b4296d26-46f7-4917-afa2-5dd8ee1672ca"
   strings:
      $s1 = "prsHelloPkt" fullword ascii
      $s2 = "pktHello" fullword ascii
      $s3 = "HELLO dwn_id=" fullword ascii
      $s4 = "getDWORD" fullword ascii
      $s5 = "outpkts" fullword ascii
      $s6 = "--- connect inPktNum=" fullword ascii
      $s7 = " RESET session savedZipData.size=" fullword ascii
      $s8 = "inpktNum=%d inpktNumConf=%d d=%d" fullword ascii
      $s9 = "Ticks=%d SrvSlotFull=%d SvZipDataOverflow=%d OpNotConf=%d" fullword ascii
      $s10 = "*LastZipDid=%d LastZipNum=%d LastZipOff=%d" fullword ascii
      $s11 = "opNum=%d opNumConf=%d d=%d" fullword ascii
      $s12 = "internalCmds" fullword ascii
      $s13 = "SrvSlot.java" fullword ascii
      $s14 = "tmLastRead" fullword ascii
      $s15 = "nAddFileEx=%d nSlowTicks=%d" fullword ascii
      $s16 = "savedZipData.size=%d" fullword ascii
      $s17 = "crKey" fullword ascii
      $s18 = "icri" fullword ascii
      $s19 = "ocri" fullword ascii
      $s20 = "icrs" fullword ascii
      $s21 = "ocrs" fullword ascii
      $s22 = "dbgTicks" fullword ascii
      $s23 = "dbgSrvSlotFull" fullword ascii
      $s24 = "dbgSvZipDataOverflow" fullword ascii
      $s25 = "dbgOpNotConf" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      8 of them
}

rule Malichus_ScSlot {
   meta:
      description = "Malichus - file ScSlot.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "87f7627e98c27620dd947e8dd60e5a124fdd3bb7c0f5957f0d8f7da6d0f90dee"
      id = "ea4069e2-4e00-482c-88e4-985f8080a7f2"
   strings:
      $s1 = "ScSlot.java" fullword ascii
      $s2 = "connect" fullword ascii
      $s3 = "SrvSlot" fullword ascii
      $s4 = "evConnect" fullword ascii
      $s5 = "evRead" fullword ascii
      $s6 = "pktCloseChannel" fullword ascii
      $s7 = "isFull" fullword ascii
      $s8 = "ScSlot" fullword ascii
      $s9 = "inbuf" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      6 of them
}

rule Malichus_Mos {
   meta:
      description = "Classes - file Mos.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "0b7b1b24f85a0107829781b10d08432db260421a7727230f1d3caa854370cb81"
      id = "9fbf893f-211f-4cd9-b6d5-879827944119"
   strings:
      $s1 = "SrvSlot" fullword ascii
      $s2 = "setDWORD" fullword ascii
      $s3 = "Mos.java" fullword ascii
      $s4 = "zipNum" fullword ascii
      $s5 = "ibuf" fullword ascii
      $s6 = "setB3" fullword ascii
   condition:
      uint32(0) == 0xbebafeca and filesize < 50KB and
      4 of them
}

/* Super Rules */

rule Malichus_Dwn_SrvSlot {
   meta:
      description = "Malichus - from files Dwn.class, SrvSlot.class"
      author = "Jai Minton, Alden Schmidt - Huntress"
      reference = "https://www.huntress.com/blog/cleo-software-vulnerability-malware-analysis"
      date = "2024-12-11"
      hash1 = "429d24e3f30c7e999033c91f32b108db48d669fde1c3fa62eff9da2697ed078e"
      hash2 = "f4e5a6027b25ede93b10e132d5f861ed7cca1df7e36402978936019930e52a16"
      id = "97143307-0d09-46c4-a4b5-6672eb87814a"
   strings:
      $s1 = "pkt_zipdata" fullword ascii
      $s2 = "nSlowTicks" fullword ascii
      $s3 = "setStat" fullword ascii
      $s4 = "nAddFileEx" fullword ascii
      $s5 = "currentTimeMillis" fullword ascii
   condition:
      ( uint32(0) == 0xbebafeca and filesize < 50KB and ( all of them )
      ) or ( all of them )
}
