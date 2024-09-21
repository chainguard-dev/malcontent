
rule curl_value : medium {
  meta:
    description = "Invokes curl"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}/
  condition:
    $ref
}

rule curl_download_val : medium {
  meta:
    description = "Invokes curl to download a file"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}-\w{0,2}[oO][\w\- :\"\/]{0,64}/
  condition:
    $ref
}


rule curl_download_ip : critical {
  meta:
    description = "Invokes curl to download a file from an IP"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
  strings:
    $arg_before = /curl [-\w\. ]{0,64}-[oO][\.a-zA-Z\- :\"\/]{0,64}([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}/
    $arg_after = /curl [-\w\. ][\.a-zA-Z\- :\"\/]{0,64}([1-9][0-9]{1,2}\.){3}[1-9][0-9]{1,2}.{0,64} -[oO]/
  condition:
    any of them
}

rule executable_calls_fetch_tool : medium {
  strings:
    $t_curl = "curl -"
    $t_wget = "wget -"
    $t_wget_http = "wget http"
    $t_quiet_output = "-q -O "
    $t_kinda_curl_o = "url -o "
    $t_kinda_curl_O = "url -O "
    $t_kinda_curl_silent_insecure = "silent --insecure"
    $t_kinda_curl_qk = "-k -q"
    $t_ftp = "ftp -"
    $t_tftp = "tftp "
    $t_ftpget = "ftpget " fullword
    $not_compdef = "#compdef"
    $not_gnu = "GNU Wget"
    $not_wget_ = "wget_"
    $not_syntax = "syntax file"
    $not_syntax_menu = "Syntax menu"
    $not_c_string = "%wget"
    $not_curlopt = "CURLOPT"
    $not_program = "@(#)PROGRAM:"
  condition:
    any of ($t_*) and none of ($not*)
}
