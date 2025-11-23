rule NikiHTTP
{
    meta:
        id = "7Hna0G06TFoi4ogjbgXnvV"
        fingerprint = "v1_sha256_0315e58657b36871b5937d06b338363de94e6bb81c19d03b92a53e2b525f56b4"
        version = "1.0"
        date = "2024-06"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze, @nsquar3"
        description = "Identifies NikiHTTP aka HTTPSpy, a versatile backdoor by (likely) Kimsuky."
        category = "MALWARE"
        malware = "NIKIHTTP"
        malware_type = "BACKDOOR"
        reference = "https://cyberarmor.tech/new-north-korean-based-backdoor-packs-a-punch/"
        hash = "3314b6ea393e180c20db52448ab6980343bc3ed623f7af91df60189fec637744"
        hash = "c94a5817fcd6a4ea93d47d70b9f2b175923a8b325234a77f127c945ae8649874"

strings:
    $cmd = {4? 8d 0d be 2f 03 00 4? 85 c0 4? 8d 15 8c 2f 03 00}
    $str_1 = "%s%sc %s >%s 2>&1" ascii wide
    $str_2 = "%s%sc %s 2>%s" ascii wide
    $str_3 = "%s:info" ascii wide
    
    //D:\02.data\03.atk-tools\engine\niki\httpSpy\..\bin\httpSpy.pdb
    $pdb_full = "\\02.data\\03.atk-tools\\"
    $pdb_httpspy = "\\bin\\httpSpy.pdb"
        
    $code = {0f 57 c0 4? 89 7? ?? 33 c0 c7 4? ?? 68 00 00 00 0f 11 4? ?? c7 4? ?? 01 00 00 00 66 4? 89 7? 00 0f 11 4? ?? 4? 89 4? ?? 0f 11 4? ?? c7 44 ?? ?? 53 71 80 60 0f 11 4? ?? c7 44 ?? ?? 71 79 7c 5c 0f 11 4? ?? c7 44 ?? ?? 6d 80 74 63 0f 11 4? ?? 88 44 ?? ?? 0f 11 4? ?? 0f 1f 44 00 00}

condition:
    uint16(0) == 0x5A4D and (
    $cmd or (2 of ($str_*)) or
    any of ($pdb_*) or $code
    )
}
