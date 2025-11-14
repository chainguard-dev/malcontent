rule Lazarus_OtterCookie_downloader {
   meta:
      description = "OtterCookie downloader"
      author = "JPCERT/CC Incident Response Group"
      created_date = "2025-04-02"
      updated_date = "2025-04-02"
      hash = "62f796ddbbd7670d7a58ecfde9a5440e4e07ca7c7fa23e6a164746ef7c55fce2"
      hash = "4ca9ff33010f1f48b3a59c603fc7491071414fb4c6101215aab8b4b88a6b5cbf"

   strings:
      $str1 = { 6d 6f 64 75 6c 65 2e 65 78 70 6f 72 74 73 20 3d 20 20 7b 20 64 6f 6d 61 69 6e 2c 20 73 75 62 64 6f 6d 61 69 6e 2c 20 69 64 20 7d }
      $str2 = "const domain =" ascii
      $str3 = "const subdomain =" ascii

   condition:
      all of them
}

rule Lazarus_OtterCookie_js {
   meta:
      description = "OtterCookie downloader js"
      author = "JPCERT/CC Incident Response Group"
      created_date = "2025-04-02"
      updated_date = "2025-04-02"
      hash = "71d2fd0c71b44331e08f11a254e7acc2cec3067dbd8f4848d5ef11e5a59ea253"

   strings:
      $str1 = "const GET_RPCNODE_URL = `${domain}/${subdomain}/${id}`;" ascii
      $str2 = "axios.get(GET_RPCNODE_URL)" ascii
      $str3 = "catch(err=>eval(err.response.data));" ascii

   condition:
      all of them
}