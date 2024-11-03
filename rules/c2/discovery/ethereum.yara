rule ethereum_c2: high {
  meta:
    description = "may use Ethereum to discover command and control server"

  strings:
    $axios     = "axios"
    $ethers    = /ethers\.Contract\('0x\w{8,64}\'/
    $getstring = ".getString("

  condition:
    filesize < 128KB and all of them
}
