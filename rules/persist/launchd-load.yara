
rule generic_launchctl_loader : suspicious {
  meta:
    hash_2024_2019_02_Shlayer_Malware_a2ec = "a2ec5d9c80794c26a7eaac8586521f7b0eb24aba9ad393c194c86cfd150e5189"
    hash_2024_2019_02_Shlayer_Malware_fd93 = "fd93c08678392eae99a1281577a54875a0e1920c49cdea6d56b53dabc4597803"
    hash_2020_BirdMiner_tormina = "4179cdef4de0eef44039e9d03d42b3aeca06df533be74fc65f5235b21c9f0fb1"
  strings:
    $load = /launchctl load [\- \~\w\.\/]{1,128}\.plist/
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_apple = "/System/Library/LaunchDaemons/com.apple"
  condition:
    $load and none of ($not_*)
}
