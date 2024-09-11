rule malware_MedusaLocker3_str {
     meta:
        description = "MedusaLocker3 ransomware"
        author = "JPCERT/CC Incident Response Group"
        hash = "d9de562ac1815bf0baad1c617c6c7f47d71f46810c348f7372a88b296d68cfae"

     strings:
        $s1 = "D:\\Education\\locker\\bin\\stub_win_x64_encrypter.pdb" ascii
        $s2 = "SOFTWARE\\PAIDMEMES" wide
        $s3 = "sMasterPublicKey" ascii
        $s4 = "[+] Keys retrieved from registry" wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       3 of them
}