rule userdata_crawler: high {
  meta:
    description = "crawls directories looking for application data"

  strings:
    $crawlCookies = "crawlUserData"
    $appdata      = "appData"

  condition:
    filesize < 1MB and all of them
}
