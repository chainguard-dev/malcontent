rule url {
  meta:
	description = "Embedded URL"
  strings:
    $tcp = /(https|http|ftp|ssh):\/\/[\w][\w\.\/\-_]{8,64}/
  condition:
    any of them
}
