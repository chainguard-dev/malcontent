import "pe"

rule apt29_dll_may2022 :  SVR G0016 apt29 NOBELIUM UNC2452 Russia
{
	meta:
        author           = "InQuest Labs"
        description      = "This signature detects .DLL files associated with recent APT29 (Russia, NOBELIUM) activity"
        created_date     = "2022-05-09"
        updated_date     = "2022-05-09"
        sample1          = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        sample2          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        sample3          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        imphash          = "b4a3f218dbd33872d0fd88a2ff95be76"
        sample_reference = "https://www.joesandbox.com/analysis/621068/0/html"
        mitre_group      = "https://attack.mitre.org/groups/G0016/"
	strings:
            $a1 = ".mp3" ascii wide nocase
            $a2 = "blank.pdf" ascii wide nocase
            $a3 = "Rock" ascii wide nocase
            $a4 = "vcruntime140.dll" ascii wide nocase

            $b1 = "RcvAddQueuedResolution" ascii wide nocase
            $b2 = "RcvResolution" ascii wide nocase
            $b3 = "AdobeAcroSup" ascii wide nocase
            $b4 = "AcroSup" ascii wide nocase
	condition:
		uint16(0) == 0x5a4d and ((filesize < 800KB) and all of ($a*) and any of ($b*))
}
