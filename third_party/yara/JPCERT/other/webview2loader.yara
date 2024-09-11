import "pe"

rule malware_webview2loader {
    meta:
      description = "Hunt webview2loader"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "D093890F60805A7A84ED218AA5246B8FAA9976A4F8379C61949985D3A254AAFF"

    strings:
      /* xor function
      48 89 C1                            mov     rcx, rax
      8B 44 24 24                         mov     eax, [rsp+58h+var_34]
      0F B7 09                            movzx   ecx, word ptr [rcx]
      31 C8                               xor     eax, ecx
      66 89 C2                            mov     dx, ax
      48 8B 44 24 48                      mov     rax, [rsp+58h+var_10]
      48 8B 4C 24 38                      mov     rcx, [rsp+58h+var_20]
      66 89 14 48                         mov     [rax+rcx*2], dx
      */
      $xorfunc1 = { 48 89 C1  8B 44 24 ?? 0F B7 09 31 C8 66 89 C2 48 8B 44 24 ?? 48 8B 4C 24 ?? 66 89 14 48 }

      $vmdetect1 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" ascii
      $vmdetect2 = "SystemManufacturer" ascii
      $vmdetect3 = "SystemProductName" ascii

     condition:
      (uint16(0) == 0x5A4D) and
      (uint32(uint32(0x3c)) == 0x00004550) and 
      (all of ($vmdetect*)) and 
      (all of ($xorfunc*)) and
      pe.imports("Wininet.dll", "InternetCrackUrlW")
}