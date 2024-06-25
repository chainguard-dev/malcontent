
rule pip_installer : high {
  meta:
    description = "Installs software using pip from python"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
    hash_2022_BeautifulSoup_new_3_0_0_setup = "975cd3986ba59ffab8df71227293dbf2534ffb572e028e3bd492d8d08ec1f090"
    hash_2022_SimpleCalc_2022_4_2_21_setup = "5b0f7b30b411d7e404786ab2266426db471a2c9d0d9cae593eb187a58a28bc4f"
  strings:
    $pip_install = "os.system('pip install"
    $pip_install_spaces = "'pip', 'install'"
    $pip_install_args = "'pip','install'"
    $pip3_install = "os.system('pip3 install"
    $pip3_install_spaces = "'pip3', 'install'"
    $pip3_install_args = "'pip3','install'"
  condition:
    any of them
}
