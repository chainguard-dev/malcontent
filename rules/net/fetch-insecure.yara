
rule curl_insecure_val : notable {
  meta:
    description = "Invokes curl in insecure mode"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2018_MacOS_CoinTicker = "c344730f41f52a2edabf95730389216a9327d6acc98346e5738b3eb99631634d"
    hash_2020_Licatrade_run = "ad27ae075010795c04a6c5f1303531f3f2884962be4d741bf38ced0180710d06"
  strings:
    $ref = /curl[\w\- ]{0,5}-k[ \-\w:\/]{0,64}/
    $ref2 = /curl[\w\- ]{0,5}--insecure[ \-\w:\/]{0,64}/
    $c_wget_insecure = /wget[\w\- ]{0,5}--no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/
  condition:
    any of them
}
