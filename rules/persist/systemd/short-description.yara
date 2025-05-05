rule systemd_short_description {
  meta:
    description = "Short or no description"
    filetypes   = "text/x-systemd"

  strings:
    $execstart  = "ExecStart="
    $short_desc = /Description=\w{,4}/ fullword

  condition:
    filesize < 4096 and all of them
}
