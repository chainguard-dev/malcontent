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

rule pip_installer : suspicious {
  meta:
	description = "Installs software using pip"
  strings:
    $ref = /pip3* add[ \w\-\_%]{0,32}/
  condition:
	$ref
}

