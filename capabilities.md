The catalog of capabilities `malcontent` reports are loosely based on the [Malware Behavior Catalog v3.1](https://github.com/MBCProject/mbc-markdown), but also includes micro-behaviors that may not be associated to malware. The MBC is very focused on Windows malware, so some liberties were taken in classifying rules.

| **Namespace** | **MBR Behavior ID** |**Description**|
|---|---|--|
| anti-behavior | **Anti-Behavioral Analysis** | makes behavioral analysis more difficult |
| anti-static | **Anti-Static Analysis** | makes static analysis more difficult |
| c2 | **Command and Control** | communicates with other compromised systems |
| collect | **Collection** | collects information from a machine or network |
| credential | **Credential Access** | accesses credentials. |
| crypto | **Cryptography** | uses elements of cryptography |
| data | **Data** | manipulates data |
| discover | **Discovery** | aims to gain knowledge about the environment.|
| evasion | **Defense Evasion** | aims to evade detection.|
| exec |  **Execution** | aims to execute code on a system |
| exfil | **Exfiltration** | aims to steal data. |
| fs | **File System** | manipulates files or directories |
| hw | **Hardware** | hardware-related behaviors |
| impact | **Impact** | aims to manipulate, interrupt, or destroy systems or data. |
| lateral | **Lateral Movement** | aims to propagate or otherwise move through an environment. |
| mem | **Memory** | manipulates memory |
| net | **Communication** | communicates with other systems |
| os | **Operating System** | makes changes to the operating system |
| persist | **Persistence** | aims to remain on a system  |
| privesc | **Privilege Escalation**| obtain higher level permissions.|
| process | **Process** | uses processes |

In general, IDs follow the form of:

`<namespace>/<resource>/<technique>`

There are some internal namespaces we use:

| **Namespace** |**Description** |
|---|---|
| 3P | third party queries (unorganized) |
| false-positives | rules to match known software |
| internal | other internal rules |
| malware | known malware |
| sec-tool | known security tools (possibly dangerous) |
| sus | suspicious content that can't be otherwise categorized |
