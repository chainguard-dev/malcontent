rule PureZip
{
    meta:
        id = "3irhYCOx5n1gPEoxWCpDiE"
        fingerprint = "c713faeaeb58701fd04353ef6fd17e4677da735318c43658d62242cd2ca3718d"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies ZIP files with a hidden file named '__.exe', as seen in a massive PureCrypt campaign in Q1 2024."
        category = "MALWARE"
        malware = "Pure"
        malware_family= "INFOSTEALER"
        hash = "ff668ef41336749df82e897c36b1438da1a21b1816716b30183024a8b62342a2"

strings:
    //This pattern is always the same. ZIP is sometimes password-protected. But typically 2 files, where __.exe is a hidden file.
    //These are all PureCrypt samples, but may drop anything from PureLogs to Agent Tesla to RedLine to...
    $exe = {5F 5F 2E 65 78 65} //__.exe

condition:
    uint16(0) == 0x4b50 and $exe in (filesize-300..filesize)
}
