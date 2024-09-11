rule darkhotel_dotNetDownloader_strings {
      meta:
        description = "detect dotNetDownloader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        reference = "internal research"
        hash1 = "d95ebbbe664b6ff75cf314b267501a5fa22e896524e6812092ae294e56b4ed44"
        hash2 = "9da9fe6af141a009f28ee37b4edba715e9d77a058b1469b4076b4ea2761e37c4"

      strings:
        $pdb = "C:\\xingxing\\snowball\\Intl_Cmm_Inteface_Buld_vesion2.6\\IMGJPS.pdb" fullword nocase
        $a1 = "4d1d3972223f623f36650c00633f247433244d5c" ascii fullword
        $b1 = "snd1vPng" ascii fullword
        $b2 = "sdMsg" ascii fullword
        $b3 = "rqPstdTa" ascii fullword
        $b4 = "D0w1ad" ascii fullword
        $b5 = "U1dAL1" ascii fullword

      condition:
        (uint16(0) == 0x5A4D) and
        (filesize<200KB)  and
        (($pdb) or ($a1) or (3 of  ($b*)))
}


rule darkhotel_lnk_strings {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "lnk file search"
        reference = "internal research"
        hash1 = "cd431575e46b80237e84cc38d3b0bc6dcd676735c889539b5efa06cec22f0560"
        hash2 = "f0d9acec522aafce3ba1c90c8af0146399a6aa74427d1cbd010a4485aacd418d"
        hash3 = "decafff59011282484d47712eec5c11cac7e17b0a5026e54d69c05e3e593ee48"

      strings:
        $hostname1 = "win-j1m3n7bfrbl" ascii fullword
        $hostname2 = "win-fe8b6nec4ks" ascii fullword
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta.exe" wide ascii
        $b1 = "TVqQAAMAAAAEAAAA" ascii

      condition:
        (uint16(0) == 0x004C) and
        ((filesize<1MB) and (filesize>200KB))  and
        ((1 of ($hostname*)) or ((1 of ($a*)) and ($b1)))
}


rule darkhotel_srdfqm_strings {
      meta:
          description = "darkhotel srdfqm.exe"
          author = "JPCERT/CC Incident Response Group"
          hash1 = "b7f9997b2dd97086343aa21769a60fb1d6fbf2d5cc6386ee11f6c52e6a1a780c"
          hash2 = "26a01df4f26ed286dbb064ef5e06ac7738f5330f6d60078c895d49e705f99394"

    	strings:
          $a1="BadStatusLine (%s)" ascii fullword
          $a2="UnknownProtocol (%s)" ascii fullword
          $a3="Request already issued" ascii fullword
          $a4="\\Microsoft\\Network\\" ascii fullword

    	condition:
          (uint16(0) == 0x5A4D) and
          (filesize<800KB)  and
        	(all of them)
}


rule darkhotel_isyssdownloader_pdbs {
    meta:
        description = "detect isyss downloader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        reference = "internal research"
        hash1 = "94c5a16cd1b6af3d545b1d60dff38dc8ad683c6e122fb577d628223dd532ab5a"

    strings:
        $b1 = {0F 84 [2-10] B8 AB AA AA 2A F7 ?? 8B C2 C1 ?? 1F 03 C2 [2-10] 03 D2 2B F2 46 83 ?? 01}
        $pdb1="C:\\Code\\india_source\\80.83\\c_isyss\\Release\\isyss.pdb" ascii fullword
        $pdb2 = "\\Release\\isyss.pdb" ascii wide
        $pdb3="C:\\Code\\india_source\\" ascii wide

    condition:
        (uint16(0) == 0x5A4D) and
        (filesize<2MB)  and
        ((1 of ($pdb*)) or ($b1))
}
