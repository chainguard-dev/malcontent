rule ditto_crypto_stealer: high {
  meta:
    description                          = "makes HTTP connections and creates archives using ditto"
    hash_2023_Downloads_589d             = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_AtomicStealer_Trading_View = "ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a"
    hash_2023_Downloads_Chrome_Update    = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"

  strings:
    $http_POST = /POST[ \/\w]{0,32}/
    $w_ditto   = /ditto -[\w\-\/ ]{0,32}/
    $w_zip     = /[\%\@\w\-\/ ]{1,32}\.zip/

  condition:
    any of ($http*) and 2 of ($w*)
}
