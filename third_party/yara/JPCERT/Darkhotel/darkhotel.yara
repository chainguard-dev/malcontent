rule darkhotel_dotNetDownloader_strings {
      meta:
        description = "detect dotNetDownloader"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "PE file search"
        reference = "internal research"



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
