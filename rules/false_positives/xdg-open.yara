rule xdg_open: override {
  meta:
    description                                    = "open"
    SECUINFRA_SUSP_Powershell_Download_Temp_Rundll = "low"

  strings:
    $comment = "Utility script to open a URL in the registered default application."
    $else    = "rundll32.exe url.dll,FileProtocolHandler \"$1\""
    $local   = "local win_path"
    $open    = "xdg-open"
    $wsl     = "open_wsl()"

  condition:
    // Unfortunately, the redpanda console is about 900MB in size
    filesize < 1024MB and all of them
}
