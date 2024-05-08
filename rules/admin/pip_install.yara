
rule pip_installer : suspicious {
  meta:
    description = "Installs software using pip from python"
    hash_2022_2022_requests_3_0_0_setup = "15507092967fbd28ccb833d98c2ee49da09e7c79fd41759cd6f783672fe1c5cc"
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
