import "pe"

rule malware_Doraemon {
    meta:
      description = "detect Doraemon"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "2d3699607194d1a2a6c1eeeb5d0e5e5e385b78d94d5053e38e3c1908c5ced1c6"
      hash2 = "95aa15baeef978b99e63a406fa06a1197f6f762047f9729f17bb49b72ead6477"
	
    strings:
      /* Mutex */
      $mut1 = {?? ?? ?? ?? 64 00 6F 00 ?? ?? ?? ?? 72 00 61 00 ?? ?? ?? ?? 65 00 6D 00 ?? ?? ?? ?? 6F 00 6E 00}

      /* xor */
      $xorfunc = {42 8B 04 02 4D 8D 40 04 41 31 40 FC}

      /* const num */
      $doubleNum1 = {9A 99 99 99 99 99 F1 3F}
	
      /* strings */
      $str1 = "Doraemon.dll" fullword ascii

    condition:
	  (uint16(0) == 0x5A4D)
	  and (filesize < 1MB)
	  and pe.imports("gdi32.dll", "BitBlt")
	  and pe.imports("kernel32.dll", "EncodePointer")
	  and pe.imports("kernel32.dll", "ReadConsoleW")
	  and pe.imports("kernel32.dll", "ReadConsoleW")
	  and (pe.characteristics & pe.DLL)
	  and all of them
}
