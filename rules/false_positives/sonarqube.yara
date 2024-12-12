rule sonarqube_tutorial_app: override {
  meta:
    description                                        = "TutorialsApp-C-wTMsCs.js"
    SIGNATURE_BASE_Suspicious_Powershell_Webdownload_1 = "high"

  strings:
    $image        = "sonarsource/sonarqube-scan"
    $license      = "/*! licenses: /vendor.LICENSE.txt */"
    $project_key  = "sonar.projectKey"
    $project_name = "sonar.projectName"

  condition:
    filesize < 192KB and all of them
}
