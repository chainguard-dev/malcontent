
rule curl_value : notable {
  meta:
    description = "Invokes curl"
  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}/
  condition:
    $ref
}

rule curl_download_val : notable {
  meta:
    description = "Invokes curl to download a file"
  strings:
    $ref = /curl [\w\.\- :\"\/]{0,64}-[oO][\w\- :\"\/]{0,64}/
  condition:
    $ref
}

rule executable_calls_fetch_tool {
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
