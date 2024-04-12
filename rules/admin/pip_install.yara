rule pip_installer : suspicious {
  meta:
	description = "Installs software using pip from python"
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

