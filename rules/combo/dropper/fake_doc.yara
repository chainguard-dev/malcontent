rule fakedoc: critical {
  meta:
    description = "downloads and execute a program after opening a document"

  strings:
    $http          = "http://"
    $https         = "https://"
    $tool_curl_o   = /curl [\w\.\- :\"\/]{0,64}-\w{0,2}[oO][\w\- :\"\/\.]{0,64}/
    $tool_wget_q   = "wget -"
    $tool_lwp      = "lwp-download"
    $cmd_bash      = "bash" fullword
    $cmd_dot_slash = /\.\/[\.\w]{1,16}/ fullword
    $cmd_rm        = "rm" fullword
    $cmd_sleep     = "sleep" fullword
    $cmd_echo      = "echo" fullword
    $cmd_chmod     = "chmod" fullword

    $open_doc = /open .{0,24}\.(pdf|xls|doc|rtf|txt)/ fullword

  condition:
    filesize < 768 and $open_doc and any of ($http*) and any of ($tool*) and any of ($cmd*)
}
