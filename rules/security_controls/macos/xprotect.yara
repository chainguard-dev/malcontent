
rule XProtectMention : medium {
  meta:
    hash_2023_JokerSpy_xcc = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
    hash_2023_JokerSpy_xcc_2 = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
    hash_2023_JokerSpy_xcc_3 = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
  strings:
    $xprotect = "XProtect"
    $not_apple = "com.apple.private"
    $not_osquery = "OSQUERY_WORKER"
    $not_kandji = "com.kandji.profile.mdmprofile"
  condition:
    $xprotect and none of ($not*)
}
