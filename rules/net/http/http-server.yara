rule http_server: medium {
  meta:
    pledge      = "inet"
    description = "serves HTTP requests"

    hash_2023_Merlin_48a7 = "48a70bd18a23fce3208195f4ad2e92fce78d37eeaa672f83af782656a4b2d07f"

  strings:
    $gin         = "gin-gonic/"
    $gin_handler = "gin.HandlerFunc"
    $listen      = "httpListen"
    $http_listen = "http.Listen"

  condition:
    filesize < 10MB and any of them
}
