rule cp_to_apple_directory : suspicious {
  meta:
    ref = "https://triangletoot.party/@philofishal@infosec.exchange/111211016916902934"
    hash_test = "77db065934b7a6d6ac5b517d98431c82bf2dc53c3aa7519e22fce8f0cd82d42a"
  strings:
    $cp_to_apple_subdir = /cp [\w\.\"\/ ]{1,128} [\w\. \"\/]{1,64}\/Application Support\/Apple[\.\w\"]{0,32}/
    $cp_to_com_apple = /cp [\w\.\"\/ ]{1,128} [\w\. \"\/]{1,64}\/com.apple[\.\w\"]{0,32}/
  condition:
    any of them
}
