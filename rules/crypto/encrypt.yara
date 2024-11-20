rule encrypt: medium {
  meta:
	description = "encrypts data"
  strings:
    $encrypt          = /[\w ]{0,16}Encrypt[\w ]{0,16}/
  condition:
    any of them
}
