
rule browser_extensions : notable {
  meta:
    description = "access Browser extensions"
    hash_2024_2019_02_Shlayer_Malware_a2ec = "a2ec5d9c80794c26a7eaac8586521f7b0eb24aba9ad393c194c86cfd150e5189"
    hash_2024_2019_02_Shlayer_Malware_b53f = "b53fab9dd4b473237a39895372aae51638b25d8f7a659c24d0a3cc21d03ef159"
    hash_2024_2019_02_Shlayer_Malware_fd93 = "fd93c08678392eae99a1281577a54875a0e1920c49cdea6d56b53dabc4597803"
  strings:
    $b_firefoxExtension = "Firefox/extensions"
    $b_safariExtension = "Safari/Extensions"
    $b_installChrome = "installChrome"
    $b_installFirefox = "installFirefox"
    $b_installSafari = "installSafari"
    $c_chromeExtension = "/Extensions"
    $c_googleChrome = "Google/Chrome"
  condition:
    any of ($b*) or all of ($c*)
}
