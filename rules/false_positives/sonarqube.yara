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

rule sonar_analyzer_override: override {
  meta:
    description                                   = "SonarQube SonarAnalyzer.CSharp.dll"
    COD3NYM_Reactor_Indicators                    = "medium"
    COD3NYM_SUSP_OBF_NET_Reactor_Indicators_Jan24 = "medium"

  strings:
    $ = "SonarAnalyzer" fullword
    $ = "SonarAnalysisContextBase" fullword
    $ = "SonarCodeFixContext" fullword
    $ = "https://www.sonarsource.com"

  condition:
    filesize > 1MB and filesize < 6MB and any of them
}
