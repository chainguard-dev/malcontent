rule ditto_crypto_stealer: high {
  meta:
    description              = "makes HTTP connections and creates archives using ditto"




  strings:
    $http_POST = /POST[ \/\w]{0,32}/
    $w_ditto   = /ditto -[\w\-\/ ]{0,32}/
    $w_zip     = /[\%\@\w\-\/ ]{1,32}\.zip/

  condition:
    any of ($http*) and 2 of ($w*)
}
