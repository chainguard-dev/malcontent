rule yum_installer : suspicious {
  meta:
	description = "Installs software using yum"
  strings:
    $ref = /yum install[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule dnf_installer : suspicious {
  meta:
	description = "Installs software using dnf"
  strings:
    $ref = /dnf install[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule rpm_installer : suspicious {
  meta:
	description = "Installs software using rpm"
  strings:
    $ref = /rpm -i[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule apt_installer : suspicious {
  meta:
	description = "Installs software using apt"
  strings:
    $ref = /apt install[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule apt_get_installer : suspicious {
  meta:
	description = "Installs software using apt-get"
  strings:
    $ref = /apt-get install[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule apk_installer : suspicious {
  meta:
	description = "Installs software using APK"
  strings:
    $ref = /apk add[ \w\-\_%]{0,32}/
  condition:
	$ref
}

rule pip_installer_regex : notable {
  meta:
	description = "Includes 'pip install' command for installing Python modules"
  strings:
    $regex = /pip[3 \'\"]{0,5}install[ \'\"\w\-\_%]{0,32}/
  condition:
	any of them
}

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

