
rule http_cookie : notable {
  meta:
    pledge = "inet"
    description = "access HTTP resources using cookies"
    ref = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2019_active_controller_middleware = "9a85e7aee672b1258b3d4606f700497d351dd1e1117ceb0e818bfea7922b9a96"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
  strings:
    $Cookie = "Cookie"
    $HTTP = "HTTP"
    $http_cookie = "http_cookie"
    $http_cookie2 = "HTTP_COOKIE"
  condition:
    any of ($http_cookie*) or ($Cookie and $HTTP)
}
