rule php_uploader {
  meta:
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_up = "c72f0194a61dcf25779370a6c8dd0257848789ef59d0108a21f08301569d4441"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
	$php = "<?php"
    $upload = "Upload"
    $uploader = "uploader"
    $x_post = "_POST"
    $x_get = "_GET"
    $copy = "copy($"
	$not_microsoft = "Microsoft Corporation"
  condition:
    $php and $copy and any of ($upload*) and any of ($x_*) and none of ($not*)
}
