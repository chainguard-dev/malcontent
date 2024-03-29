rule vnc_user : notable {
  meta:
    hash_2020_BirdMiner_arachnoidal = "904ad9bc506a09be0bb83079c07e9a93c99ba5d42ac89d444374d80efd7d8c11"
    hash_2023_Linux_Malware_Samples_1d28 = "1d2800352e15175ae5fa916b48a96b26f0199d9f8a9036648b3e44aa60ed2897"
    hash_2023_Linux_Malware_Samples_5a62 = "5a628dc26dae0309941d70021cfbb4281189f85b074bf3e696058d73c4609101"
    hash_2023_Linux_Malware_Samples_d13f = "d13fd21514f7ee5e58343aa99bf551c6a56486731c50daefcce233fdb162def8"
    hash_2023_Linux_Malware_Samples_e036 = "e0367097a1450c70177bbc97f315cbb2dcb41eb1dc052f522c9e8869e084bd0f"
  strings:
    $vnc_password = "vnc_password"
    $vnc_ = "VNC_"
    $vnc_port = ":5900"
	$not_synergy = "SYNERGY"
  condition:
    any of ($vnc*) and none of ($not*)
}
