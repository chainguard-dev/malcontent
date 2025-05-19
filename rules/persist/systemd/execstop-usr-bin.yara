rule usr_bin_execstop: medium {
  meta:
    ref         = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
    description = "Runs program from /usr/bin at stop"
    filetypes   = "service"

  strings:
    $execstop = /ExecStop=\/usr\/bin\/[\w\.]{0,32}/
    $finalrd  = "ExecStop=/usr/bin/finalrd"

  condition:
    filesize < 4KB and $execstop and not $finalrd
}
