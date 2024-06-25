rule ditto_crypto_stealer : high {
  meta:
    description = "makes HTTP connections and creates archives using ditto"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
  strings:
    $http = "http"
    $http_POST = /POST[ \/\w]{0,32}/
    $w_ditto = /ditto -[\w\-\/ ]{0,32}/
    $w_zip = /[\w\-\/ ]{0,32}\.zip/
  condition:
    any of ($http*) and 2 of ($w*)
}
