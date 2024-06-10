rule Unk_Crime_Downloader_2
{
    meta:
        id = "uuvhiMCrxhHFwTkSF2Tqv"
        fingerprint = "9e6a26d06965366eaa5c3ad98fb2b120187cfb04a935e6a82effc58b23a235f0"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies what appears to be related to PureLogs stealer, but it's likely a 2nd stage with the final stage to be downloaded."
        category = "MALWARE"
        malware = "PURELOGS"
        malware_type = "DOWNLOADER"
        hash = "443b3b9929156d71ed73e99850a671a89d4d0d38cc8acc7f286696dd4f24895e"

strings:
    $unc = "UNCNOWN" ascii wide fullword
    $anti_vm1 = "WINEHDISK" ascii wide fullword
    $anti_vm2 = "(VMware|Virtual|WINE)" ascii wide
    $click_1 = "TOffersPanel" ascii wide
    $click_2 = "TOfferLabel" ascii wide
    $click_3 = "TOfferCkb" ascii wide
    $campaign = "InstallComaignsThread" ascii wide
    $net_call = "/new/net_api" ascii wide

condition:
    4 of them
}
