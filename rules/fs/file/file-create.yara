rule creat: medium {
  meta:
    description                          = "create a new file or rewrite an existing one"
    syscalls                             = "open"
    ref                                  = "https://man7.org/linux/man-pages/man3/creat.3p.html"
    hash_2024_Downloads_8cad             = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_Linux_Malware_Samples_14a3 = "14a33415e95d104cf5cf1acaff9586f78f7ec3ffb26efd0683c468edeaf98fd7"
    hash_2023_Linux_Malware_Samples_d0a3 = "d0a3421d977bcce8e867ec10e4790aa4b69353edf9d5ddfc3dd0480a18878a19"

  strings:
    $system = "creat" fullword

  condition:
    all of them in (1000..3000)
}
