
rule curl_agent_val : high {
  meta:
    description = "Invokes curl with a custom user agent"
  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}-a[ "][\w\- :\"\/]{0,64}/
  condition:
    $ref
}

rule urllib_oneliner : high {
  meta:
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
  strings:
    $urllib_req = "import urllib.request; urllib.request.urlretrieve"
  condition:
    any of them
}

rule high_fetch_command_val : high {
  meta:
    description = "high-risk fetch command"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
    hash_2023_Chaos_27cd = "27cdb8d8f64ce395795fdbde10cf3a08e7b217c92b7af89cde22abbf951b9e99"
  strings:
    $c_curl_d = /curl [\- \w]{0,16}-[dOok][\/\- \w\%\(\{\}\'\"\)\$\:\.]{0,128}/
    $c_curl_insecure = /curl [\- \w]{0,128}--insecure[\/\- \w\%\(\{\}\'\"\)\$\:\.]{0,128}/
    $c_kinda_curl_silent_insecure = "--silent --insecure"
    $c_kinda_curl_silent_k = "-k --insecure"
    $c_kinda_curl_k_q = "-k -q"
    $c_wget_insecure = /wget --no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$\:]{0,128}/
    $not_curl_response_code = "%{response_code}"
    $not_oh_my_zsh = "oh-my-zsh-master"
    $not_localhost = "curl -k https://localhost"
    $not_127_0_0_1 = "curl -k https://127.0.0.1"
  condition:
    any of ($c*) and none of ($not*)
}
