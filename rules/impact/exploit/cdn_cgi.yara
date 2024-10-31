rule cdn_cgi : medium {
  meta:
    description = "Mentions Cloudflare cdn-cgi endpoint"
    hash_2023_Downloads_5f73 = "5f73f54865a1be276d39f5426f497c21e44a309e165e5e2d02f5201e8c1f05e0"
    hash_2024_Downloads_fd0b = "fd0b5348bbfd013359f9651268ee67a265bce4e3a1cacf61956e3246bac482e8"
    hash_2023_Linux_Malware_Samples_1776 = "17769e5eb8cf401135e55b6c7258d613365baa6e69fb1c17c06806dad76bcc58"
  strings:
    $cdn_cgi = "cdn-cgi" fullword
    $not_ct = "https://report-uri.cloudflare.com/cdn-cgi/"
  condition:
    $cdn_cgi and not $not_ct
}

rule cdn_cgi_xor : high {
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


rule cdn_cgi_captcha : high {
  meta:
    description = "Mentions Cloudflare cdn-cgi Captcha endpoint"
  strings:
    $cdn_cgi = "cdn-cgi" fullword
    $chk_captcha = "chk_captcha" fullword
  condition:
    all of them
}