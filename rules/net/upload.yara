
rule upload : medium {
  meta:
    description = "uploads files"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_up = "c72f0194a61dcf25779370a6c8dd0257848789ef59d0108a21f08301569d4441"
  strings:
    $ref = /upload\w{0,16}/
    $ref2 = /UPLOAD\w{0,16}/
    $ref3 = /Upload\w{0,16}/
  condition:
    any of them
}

rule curl_upload_command : medium {
  meta:
    description = "Uses curl to upload data"
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
  strings:
    $long_upload_file = /\w{0,1}--upload-file[ \w\$\-\=\@:\/\.\"\-]{0,128}/
    $long_inesecure_data = /[ \w\$\-\=\@:\/\.\"\-]{0,128}--insecure --data[ \w\$\-\=\@:\/\.\"\-]{0,128}/
	$curl = "curl" fullword
    $mixed = /[ \w\$\-\=\@:\/\.\"\-]{0,128}-k --data[ \w\$\-\=\@:\/\.\"\-]{0,128}/
    $short = /[ \w\$\-\=\@:\/\.\"\-]{0,128}-k -d[ \w\$\-\=\@:\/\.\"\-]{0,128}/
  condition:
	any of ($long*) or $mixed or ($curl and $short)
}
