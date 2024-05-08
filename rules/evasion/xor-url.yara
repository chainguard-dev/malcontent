
rule xor_url : suspicious {
  meta:
    description = "URL hidden using XOR encryption"
    hash_2023_ZIP_locker_AArch_64 = "724eb1c8e51f184495cfe81df7049531d413dd3e434ee3506b6cc6b18c61e96d"
    hash_2023_ZIP_locker_ARMv5_32 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
    hash_2023_ZIP_locker_ARMv6_32 = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
  strings:
    $http = "http:" xor(1-31)
    $https = "https:" xor(1-31)
    $ftp = "ftp:/" xor(1-31)
    $office = "office" xor(1-31)
    $google = "google." xor(1-31)
    $microsoft = "microsoft" xor(1-31)
    $apple = "apple." xor(1-31)
    $user_agent = "User-Agent" xor(1-31)
    $http2 = "http://" xor(33-255)
    $https2 = "https://" xor(33-255)
    $ftp2 = "ftp://" xor(33-255)
    $google2 = "google." xor(33-255)
    $microsoft2 = "microsoft" xor(33-255)
    $apple2 = "apple." xor(33-255)
    $user_agent2 = "User-Agent" xor(33-255)
  condition:
    any of them
}
