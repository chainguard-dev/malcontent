rule http_server: medium {
  meta:
    pledge      = "inet"
    description = "serves HTTP requests"

  strings:
    $gin         = "gin-gonic/"
    $gin_handler = "gin.HandlerFunc"
    $listen      = "httpListen"
    $http_listen = "http.Listen"
    $http_server = "http.server"

  condition:
    filesize < 10MB and any of them
}
