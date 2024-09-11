rule SteelClover_PowerHarbor_str {
     meta:
        description = "PowerHarbor in SteelClover"
        author = "JPCERT/CC Incident Response Group"
        hash = "f4b3b3624b4cfdd20cb44ace9d7dad26037fa5462e03b17fccf8d5049e961353"

     strings:
        $s1 = "[string]$campaign_id," ascii
        $s2 = "[string]$RSABotPrivateKey," ascii
        $s3 = "[string]$RSAPanelPubKey," ascii
        $s4 = "function Check-DiskDrive {" ascii
        $s5 = "function Check-DisplayConfiguration {" ascii
        $s6 = "function Check-VideoController {" ascii
        $s7 = "$is_vm = Is-VM" ascii
        $s8 = "function Is-VM {" ascii

     condition:
        5 of them
}

rule SteelClover_PowerShell_str {
    meta:
        description = "PowerShell in SteelClover"
        author = "JPCERT/CC Incident Response Group"
        hash = "05e6f7a4184c9688ccef4dd17ae8ce0fe788df1677c6ba754b37a895a1e430e9"

    strings:
        $a1 = "function Add-Encryption" ascii
        $a2 = "function Remove-Encryption" ascii
        $a3 = "Remove-Encryption -FolderPath $env:APPDATA -Password" ascii
        $b1 = "function Install-GnuPg" ascii
        $b2 = "Install-GnuPG -DownloadFolderPath $env:APPDATA" ascii

     condition:
        all of ($a*) or all of ($b*)
}