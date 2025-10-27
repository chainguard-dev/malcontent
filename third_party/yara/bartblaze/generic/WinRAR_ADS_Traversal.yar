rule WinRAR_ADS_Traversal
{
    meta:
        id = "7Eg0fdIJ67bBekR1rpUlNJ"
        fingerprint = "v1_sha256_7c52c7e31793540231f5a317dfc6b1cbcc40dc78a4084bf9271ea7c7da8e5e33"
        version = "1.0"
        date = "2025-08-12"
        modified = "2025-08-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies potential ADS traversal in RAR archives."
        category = "INFO"
        reference = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"

    strings:
        $rar= { 52 61 72 21 }
        $ads_traversal = ":..\\..\\..\\..\\..\\..\\..\\..\\" ascii wide nocase
        $zone_identifier = "Zone.Identifier" ascii wide nocase
        $lnk = "lnk" ascii wide nocase
        $bat = "bat" ascii wide nocase
        $vbs = "vbs" ascii wide nocase
        $js = "js" ascii wide nocase
        $exe = "exe" ascii wide nocase
 
    condition:
        $rar at 0 and $ads_traversal
        and not $zone_identifier
        and any of ($lnk, $bat, $vbs, $js, $exe)
}
