rule curl_value: medium {
  meta:
    description = "Invokes curl"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}/

  condition:
    $ref
}

rule curl_sudo_pipe: medium {
  meta:
    description = "Invokes curl and executes content via sudo"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}.{0,128}\|\s{0,2}sudo/

  condition:
    $ref
}

rule curl_python_pipe: high {
  meta:
    description = "fetches python and executes python script"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}.{0,128}\|\s{0,2}python.{0,8}/

  condition:
    $ref
}

rule curl_sudo_python_pipe: critical {
  meta:
    description = "fetches python and executes python script using sudo"

  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}.{0,128}\|\s{0,2}sudo python.{0,8}/

  condition:
    $ref
}

rule curl_xxd: high {
  meta:
    description = "Invokes curl and generates hex codes"

  strings:
    $ref = "xxd -p"

  condition:
    filesize < 8KB and curl_value and $ref
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

private rule fetch_macho {
  condition:
    uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962 or uint32(0) == 3405691583 or uint32(0) == 3216703178
}

private rule fetch_elf {
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
    filetypes   = "elf,macho"

  strings:
    $t_curl_O  = /[a-z]url [-\w ]{0,8}-[oOk] [ \w\:\/\-\.\"]{0,32}/
    $t_wget    = /wget [ \w\:\/\-\.\"]{4,32}/
    $t_curl_qk = /[a-z]url [-\w ]{0,16} -(-silent|q) -(-insecure|k) [ \w\:\/\-\.\"]{0,32}/
    $t_curl_kq = /[a-z]url [-\w ]{0,16} -(-insecure|k) -(-silent|q) [ \w\:\/\-\.]{0,32}/
    $t_tftp    = /tftp [ \w\:\/\-\.\"]{0,32}/

    $not_tftp     = "Illegal TFTP operation"
    $not_tftp_err = "tftp error"

  condition:
    filesize < 10MB and (fetch_elf or fetch_macho) and any of ($t*) and none of ($not*)
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
    description = "one-line Python script to download files"

  strings:
    $urllib_req = "import urllib.request; urllib.request.urlretrieve"

  condition:
    any of them
}

rule curl_insecure_val: medium {
  meta:
    description = "Invokes curl in insecure mode"

  strings:
    $ref             = /curl[\w\- ]{0,5}-k[ \-\w:\/]{0,64}/
    $ref2            = /curl[\w\- ]{0,5}--insecure[ \-\w:\/]{0,64}/
    $c_wget_insecure = /wget[\w\- ]{0,5}--no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/

  condition:
    any of them
}

rule high_fetch_command_val: high {
  meta:
    description = "high-risk fetch command"

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

    $x_chmod      = "chmod" fullword
    $x_Chmod      = "Chmod" fullword
    $not_elastic1 = "/*! Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one or more contributor license agreements."
    $not_elastic2 = "* Licensed under the Elastic License 2.0; you may not use this file except in compliance with the Elastic License 2.0. */"
    $x_exe        = ".exe"
    $x_rename     = "rename"
    $x_rundll32   = "rundll32"

  condition:
    filesize < 1MB and any of ($c*) and any of ($x*) and none of ($not*)
}
