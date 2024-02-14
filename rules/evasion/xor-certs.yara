
rule xor_certs : suspicious {
  meta:
	description = "key material obfuscated using xor"
  strings:
    $public = "PUBLIC" xor(1-31)
    $public2 = "PUBLIC" xor(33-255)
    $private = "PRIVATE" xor(1-31)
    $private2 = "PRIVATE" xor(33-255)
    $ssh = "ssh-rsa" xor(1-31)
    $ssh2 = "ssh-rsa" xor(33-255)
  condition:
    any of them
}