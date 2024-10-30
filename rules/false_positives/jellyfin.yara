rule swashbuckle_dll: override {
  meta:
    description      = "Swashbuckle.AspNetCore.ReDoc.dll"
    infection_killer = "medium"

  strings:
    $description = "Middleware to expose an embedded version of Redoc from an ASP.NET Core application"
    $license     = "&Copyright (c) 2016-2024 Richard Morris"
    $repository  = "https://github.com/domaindrivendev/Swashbuckle.AspNetCore"

  condition:
    filesize < 1MB and all of them
}
