rule bin_sh_execstop: medium {
  meta:
    ref         = "https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html"
    description = "Runs shell script at stop"
    filetypes   = "service"

  strings:
    $execstop = /ExecStop=\/bin\/sh\/[\w\. \-\'\"]{0,64}/

  condition:
    filesize < 4KB and $execstop
}
