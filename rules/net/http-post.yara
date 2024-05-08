
rule http_post : notable {
  meta:
    pledge = "inet"
    description = "submit content to websites"
  strings:
    $POST = "POST"
    $h_HTTP = "HTTP"
    $http = "http"
  condition:
    $POST and any of ($h*)
}

rule form_data_reference : notable {
  meta:
    description = "submit form content to websites"
  strings:
    $f_content_dispo_name = "Content-Disposition: form-data; name="
    $f_multipart = "multipart/form-data; boundary="
  condition:
    any of ($f_*)
}
