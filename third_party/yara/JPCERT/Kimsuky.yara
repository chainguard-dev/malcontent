rule Kimsuky_downloader_vbs
{
    meta:
        description = "VBS file to download Powershell used by Kimsuky" 
        author = "JPCERT/CC Incident Response Group" 
        hash = "36997232fc97040b099fedc4f0c5bf7aed5d468533a27924dc981b94ca208d71" 

    strings:
        $s1 = "PokDoc -Slyer 'xxx'" ascii
        $s2 = "InfoKey -ur 'xxx'" ascii
        $s3 = "iex (wget xxx" ascii
        $s4 = "pow_cmd = Replace(pow_cmd, \"xxx\", uri)" ascii

    condition:
        3 of them
}

rule Kimsuky_PokDoc_ps1
{
    meta:
        description = "Powershell file to collect device information used by Kimsuky" 
        author = "JPCERT/CC Incident Response Group" 
        hash = "82dbc9cb6bf046846046497334c9cc28082f151e4cb9290ef192a85bdb7cc6c8" 

    strings:
        $s1 = "Function PokDoc {" ascii
        $s2 = "Param ([string] $Slyer)" ascii
        $s3 = "boundary`r`nContent-Disposition: form-data; name=\";" ascii
        $s4 = "$conDisp`\"file`\"; filename=`\"" ascii

    condition:
        3 of them
}

rule Kimsuky_InfoKey_ps1
{
    meta:
        description = "Powershell file with keylogger functionality used by Kimsuky" 
        author = "JPCERT/CC Incident Response Group" 
        hash = "cc2355edb2e2888bae37925ec3ddce2c4c7a91973e89ee385074c337107175ca" 

    strings:
        $s1 = "Global\\AlreadyRunning19122345" ascii
        $s2 = "if(($upTick -eq 0) -or (($curTick - $upTick) -gt $tickGap)){" ascii
        $s3 = "`n----- [Clipboard] -----`n\" + [Windows.Clipboard]::GetText()"
        $s4 = "`n----- [\" + $t + \"] [\" + $curWnd.ToString() + \"] -----`n"

    condition:
        3 of them
}

rule kimsuky_downloader_pe
{
    meta:
        description = "A dotnet executable that downloads the vbs file used by Kimsuky"
        author = "JPCERT/CC Incident Response Group"
        hash = "E5226F945E3EC29868891EDC63E64CAECAE0F9EEF1627EBA826AC08809339A39"

    strings:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = "_CorExeMain" ascii
        $s1 = "powershell.exe" wide
        $s2 = "-windowstyle hidden -c wscript '" wide
        $s3 = "RGVjb2RlID0gIiI6Zm9yIGk" wide
        $s4 = "D:\\work\\Virus\\1_troy\\c#\\pack_2023\\2023-06\\work\\obj\\Debug\\ConsoleApplication1.pdb" ascii
        $s5 = {00 07 11 ?? 25 17 59 13 ?? 91 20 92 00 00 00 40 ?? ?? 00 00 07 11 ?? 91 20 F0 00 00 00 40}

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        all of ($dotnet*) and
        3 of ($s*)
}
