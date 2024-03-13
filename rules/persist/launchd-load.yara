
rule generic_launchctl_loader : suspicious {
  meta:
    hash_2020_BirdMiner_tormina = "4179cdef4de0eef44039e9d03d42b3aeca06df533be74fc65f5235b21c9f0fb1"
    hash_2023_CoinMiner_lauth = "fe3700a52e86e250a9f38b7a5a48397196e7832fd848a7da3cc02fe52f49cdcf"
    hash_2018_CookieMiner_uploadminer = "6236f77899cea6c32baf0032319353bddfecaf088d20a4b45b855a320ba41e93"
    hash_2017_Dockster = "8da09fec9262d8bbeb07c4e403d1da88c04393c8fc5db408e1a3a3d86dddc552"
    hash_2016_Eleanor_eleanr_script = "2c752b64069e9b078103adf8f5114281b7ce03f1ca7a995228f180140871999e"
  strings:
    $load = /launchctl load [\- \~\w\.\/]{1,128}\.plist/
    $not_osquery = "OSQUERY_WORKER"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_kandji = "com.kandji.profile.mdmprofile"
    $not_apple = "/System/Library/LaunchDaemons/com.apple"
  condition:
    $load and none of ($not_*)
}
