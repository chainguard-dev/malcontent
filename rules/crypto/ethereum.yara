rule ethereum: medium {
  meta:
    description = "uses Ethereum"
    filetypes   = "js,ts"

  strings:
    $ethers = "require(\"ethers\");"

  condition:
    filesize < 128KB and all of them
}
