rule crypto_locker {
  meta:
    ref = "https://www.sentinelone.com/blog/dark-angels-esxi-ransomware-borrows-code-victimology-from-ragnarlocker/"

  strings:
    $c_locked      = "locked" fullword
    $c_kill        = "kill" fullword
    $c_Path        = "Path" fullword
    $c_Lock_file   = "Lock" fullword
    $c_Files_Found = "Files Found"
    $c_README      = "README" fullword
    $c_Done        = "Done" fullword
    $c_encrypt     = "encrypt" fullword
    $c_Queue       = "Queue" fullword
    $c_Round       = "Round" fullword
    $c_cores       = "cores" fullword
    $x_browser     = "TOR Browser" nocase
    $x_tor         = " TOR "
    $x_download    = "torproject.org"
    $x_onion       = /\w\.onion\W/
    $x_btc         = "BTC" fullword
    $not_xul       = "XUL_APP_FILE"

  condition:
    filesize < 25MB and 5 of ($c*) and 2 of ($x*) and none of ($not*)
}
