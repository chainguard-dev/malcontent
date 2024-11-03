rule http_server: medium {
  meta:
    pledge                   = "inet"
    description              = "serves HTTP requests"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
    hash_2023_Manjusaka_955e = "955e9bbcdf1cb230c5f079a08995f510a3b96224545e04c1b1f9889d57dd33c1"
    hash_2023_Merlin_48a7    = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"

  strings:
    $gin         = "gin-gonic/"
    $gin_handler = "gin.HandlerFunc"
    $listen      = "httpListen"
    $http_listen = "http.Listen"

  condition:
    filesize < 10MB and any of them
}
