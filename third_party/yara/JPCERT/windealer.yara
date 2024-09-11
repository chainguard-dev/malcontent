rule malware_WinDealer {
    meta:
      description = "detect WinDealer LuoYu"
      author = "JPCERT/CC Incident Response Group"
      hash2 = "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128"
      hash3 = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
      hash4 = "0c365d9730a10f1a3680d24214682f79f88aa2a2a602d3d80ef4c1712210ab07"
      hash5 = "2eef273af0c768b514db6159d7772054d27a6fa8bc3d862df74de75741dbfb9c"

    strings:
      /* monitoring files */
      $moni_1 = "~B5D9" fullword ascii
      $moni_2 = "65ce-731bffbb" fullword ascii
      $moni_3 = "~BF24" fullword ascii
      $moni_4 = "~BF34" fullword ascii
      $moni_5 = "63ae-a20cf808" fullword ascii
      $moni_6 = "28e4-20a6acec" fullword ascii
      $moni_7 = "~FFFE" fullword ascii
      $moni_8 = "~B5BE" fullword ascii
      $moni_9 = "~B61A" fullword ascii
      $moni_10 = "d0c8-b9baa92f" fullword ascii
      $moni_11 = "~CE14" fullword ascii
      $moni_12 = "070a-cf37dcf5"  fullword ascii

      /* code, strings */
      $auth1 = {DB 70 20 24}
      $auth2 = {2A C6 87 47}
      $str_1 = "Shell Folders" fullword ascii
      $str_2 = "Common AppData" fullword ascii
      $str_3 = "%s\\*.a" fullword ascii
      $str_4 = "ackfile" fullword ascii
      $str_5 = "YYYY" fullword ascii
      $str_6 = "%s\\*.*" fullword ascii
      $str_7 = "%s\\c25549fe" fullword ascii

    condition:
	  (uint16(0) == 0x5A4D)
	  and (filesize < 3MB)
	  and (8 of ($moni_*))
	  and (all of ($auth*))
      and (5 of ($str_*))
}