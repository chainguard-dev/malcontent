rule cp_to_apple_directory: high {
  meta:
    ref = "https://triangletoot.party/@philofishal@infosec.exchange/111211016916902934"

  strings:
    $cp_to_apple_subdir = /cp [\w\.\"\/ ]{1,128} [\w\. \"\/]{1,64}\/Application Support\/Apple[\.\w\"]{0,32}/
    $cp_to_com_apple    = /cp [\w\.\"\/ ]{1,128} [\w\. \"\/]{1,64}\/com.apple[\.\w\"]{0,32}/

  condition:
    any of them
}
