
rule cdn_cgi : notable {
  meta:
    description = "Mentions Cloudflare cdn-cgi endpoint"
  strings:
    $cdn_cgi = "cdn-cgi" fullword
    $not_ct = "https://report-uri.cloudflare.com/cdn-cgi/"
  condition:
    $cdn_cgi and not $not_ct
}

rule cdn_cgi_xor : suspicious {
  meta:
    description = "Mentions Cloudflare cdn-cgi endpoint, XOR"
    hash_2023_Unix_Dropper_Mirai_d4b9d82859b3624f50c5ad0972f11aa92d19c44dbaaaeb556e0a8_elf = "ee96dc17057d4b9d82859b3624f50c5ad0972f11aa92d19c44dbaaaeb556e0a8"
    hash_2023_Unix_Trojan_DarkNexus_6387 = "63873589029ec09e3e73ffa581968026bf38ad446f593d6c85ec853f9982499f"
    hash_2023_Unix_Trojan_DarkNexus_e41b = "e41b20b1dc5b3e5a0eea9af3277d94cbc5833d23c53b800993d89bb20e5158a6"
  strings:
    $cdn_cgi = "cdn-cgi" xor(1-31)
    $cdn_cgi2 = "cdn-cgi" xor(33-255)
  condition:
    any of them
}
