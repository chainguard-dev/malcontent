
rule conti_alike : high {
  meta:
    description = "Reads directories, renames files, encrypts files"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2023_Downloads_8b57 = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
    hash_2023_Downloads_f864 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
  strings:
    $readdir = "readdir" fullword
    $rename = "rename" fullword
    $enc1 = "encrypted by"
    $enc2 = "RSA PUBLIC KEY"
    $enc3 = "Encrypting file"
    $enc4 = "files_encrypted"
    $enc5 = "encrypts files"
  condition:
    filesize < 1MB and $readdir and $rename and any of ($enc*)
}
