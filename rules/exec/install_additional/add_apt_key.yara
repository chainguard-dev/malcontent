rule apt_add_key: medium {
  meta:
    description = "Installs apt repository keys"

  strings:
    $ref = /apt-key add[ \w\-\_%]{0,32}/

  condition:
    $ref
}
