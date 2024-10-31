rule syn_cookie: medium {
  meta:
    description                          = "references SYN cookies, used to resist DoS attacks"
    ref                                  = "https://en.wikipedia.org/wiki/SYN_cookies"
    hash_2023_Linux_Malware_Samples_5a62 = "5a628dc26dae0309941d70021cfbb4281189f85b074bf3e696058d73c4609101"
    hash_2023_Linux_Malware_Samples_e036 = "e0367097a1450c70177bbc97f315cbb2dcb41eb1dc052f522c9e8869e084bd0f"

  strings:
    $syncookie  = "syncookie"
    $syn_cookie = "syn_cookie"

  condition:
    any of them
}
