rule execstop_elsewhere: medium {
  meta:
    ref         = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
    description = "Runs program from unexpected directory at stop"
    filetypes   = "service"

  strings:
    $execstop     = /ExecStop=\/[\w\.\_\-]{2,64}/
    $not_usr_bin  = "ExecStop=/usr/bin"
    $not_usr_sbin = "ExecStop=/usr/sbin"
    $not_bin      = "ExecStop=/bin"
    $not_usr_lib  = "ExecStop=/usr/lib"

  condition:
    filesize < 4KB and $execstop and none of ($not*)
}
