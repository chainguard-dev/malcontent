
rule url {
  meta:
	description = "Embedded URL"
  strings:
    $tcp = /[a-z]{3,4}:\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}