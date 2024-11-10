rule curl_value: medium {
  meta:
    description = "Invokes curl"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}/

  condition:
    $ref
}

rule curl_download_val: medium {
  meta:
    description = "Invokes curl to download a file"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}-\w{0,2}[oO][\w\- :\"\/]{0,64}/

  condition:
    $ref
}

rule curl_download_ip: critical {
  meta:
    description = "Invokes curl to download a file from an IP"

  strings:
    $arg_before = /curl [-\w\. ]{0,64}-[oO][\.a-zA-Z\- :\"\/]{0,64}([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}.{0,32}/
    $arg_after  = /curl [-\w\. ][\.a-zA-Z\- :\"\/]{0,64}([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}.{0,64} -[oO]/

  condition:
    any of them
}

private rule macho {
  condition:
    uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178
}

private rule elf {
  condition:
    uint32(0) == 1179403647
}

rule fetch_tool: medium {
  meta:
    description = "calls a URL fetch tool"

  strings:
    $t_curl_O  = /[a-z]url [-\w ]{0,8}-[oOk] [ \w\:\/\-\.]{0,32}/
    $t_wget    = /wget [ \w\:\/\-\.]{4,32}/
    $t_curl_qk = /[a-z]url [-\w ]{0,16} -(-silent|q) -(-insecure|k) [ \w\:\/\-\.]{0,32}/
    $t_curl_kq = /[a-z]url [-\w ]{0,16} -(-insecure|k) -(-silent|q) [ \w\:\/\-\.]{0,32}/
    $t_tftp    = /tftp [ \w\:\/\-\.]{0,32}/

  condition:
    filesize < 1MB and any of ($t_*)
}

rule binary_calls_fetch_tool: high {
  meta:
    description = "binary calls fetch tool"
    filetypes   = "macho,elf"

  strings:
    $t_curl_O  = /[a-z]url [-\w ]{0,8}-[oOk] [ \w\:\/\-\.\"]{0,32}/
    $t_wget    = /wget [ \w\:\/\-\.\"]{4,32}/
    $t_curl_qk = /[a-z]url [-\w ]{0,16} -(-silent|q) -(-insecure|k) [ \w\:\/\-\.\"]{0,32}/
    $t_curl_kq = /[a-z]url [-\w ]{0,16} -(-insecure|k) -(-silent|q) [ \w\:\/\-\.]{0,32}/
    $t_tftp    = /tftp [ \w\:\/\-\.\"]{0,32}/

    $not_tftp     = "Illegal TFTP operation"
    $not_tftp_err = "tftp error"

  condition:
    filesize < 10MB and (elf or macho) and any of ($t*) and none of ($not*)
}

rule curl_agent_val: high {
  meta:
    description = "Invokes curl with a custom user agent"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}-a[ "][\w\- :\"\/]{0,64}/

  condition:
    $ref
}

rule urllib_oneliner: high {
  meta:
    hash_2023_Qubitstrike_branch_raw_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Qubitstrike_mi            = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $urllib_req = "import urllib.request; urllib.request.urlretrieve"

  condition:
    any of them
}

rule curl_insecure_val: medium {
  meta:
    description                = "Invokes curl in insecure mode"
    hash_2024_Downloads_a031   = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2020_Licatrade_run    = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"

  strings:
    $ref             = /curl[\w\- ]{0,5}-k[ \-\w:\/]{0,64}/
    $ref2            = /curl[\w\- ]{0,5}--insecure[ \-\w:\/]{0,64}/
    $c_wget_insecure = /wget[\w\- ]{0,5}--no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/

  condition:
    any of them
}

rule high_fetch_command_val: high {
  meta:
    description          = "high-risk fetch command"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
    hash_2023_Chaos_27cd = "27cdb8d8f64ce395795fdbde10cf3a08e7b217c92b7af89cde22abbf951b9e99"

  strings:
    $c_curl_d                     = /curl [\- \w]{0,16}-[dOok][\/\- \w\%\(\{\}\'\"\)\$\:\.]{0,128}/
    $c_curl_insecure              = /curl [\- \w]{0,128}--insecure[\/\- \w\%\(\{\}\'\"\)\$\:\.]{0,128}/
    $c_kinda_curl_silent_insecure = "--silent --insecure"
    $c_kinda_curl_silent_k        = "-k --insecure"
    $c_kinda_curl_k_q             = "-k -q"
    $c_wget_insecure              = /wget --no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$\:]{0,128}/
    $not_curl_response_code       = "%{response_code}"
    $not_oh_my_zsh                = "oh-my-zsh-master"
    $not_localhost                = "https://localhost"
    $not_127_0_0_1                = "https://127.0.0.1"
    $not_dump_header              = "curl --silent --dump-header"
    $not_silent_key               = "curl --silent --key"
    $not_s_key                    = "curl -s --key"
    $not_local                    = "curl -ks https://localhost"
    $not_continue                 = "--continue-at"
    $not_pciid                    = "https://pci-ids.ucw.cz"

    $x_chmod    = "chmod" fullword
    $x_Chmod    = "Chmod" fullword
    $x_exe      = ".exe"
    $x_rename   = "rename"
    $x_rundll32 = "rundll32"

  condition:
    filesize < 1MB and any of ($c*) and any of ($x*) and none of ($not*)
}
