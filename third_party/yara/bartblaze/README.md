# About
## What is this?
A repo containing some of my privately developed Yara rules.

## Why?
To contribute to the community.

## Can I use these rules?
Of course! That's why I created this repo. 

You can use them in your detection systems. For example, [CAPE sandbox](https://github.com/kevoreilly/CAPEv2), [MalwareBazaar](https://bazaar.abuse.ch/), [UnPac.me](https://www.unpac.me/) and [VirusTotal](https://www.virustotal.com/) (must be logged in, signup is free) and others are using these rules. Furthermore, the rules can work natively with [AssemblyLine](https://www.cyber.gc.ca/en/tools-services/assemblyline) due to the CCCS Yara rule standard adoption.

All rules are TLP:CLEAR, so you can use and distribute them freely. Please retain the meta. 

## Help! A generic rule is hitting my software!
If one of the rules in the [generic](https://github.com/bartblaze/Yara-rules/tree/master/rules/generic) rules section hits on your software: this is not a false positive. It is simply an objective fact that, for example, your software has been compiled or wrapped using AutoIT. It equally does **not** mean your software is malicious. 

The Yara rules presented here do **not** influence antivirus detection results in any manner. If your software is detected by an antivirus or antimalware company, **you need to contact them directly**.

Note the `meta` section also mentions `category = "INFO"`, in which case it is a purely generic or informational rule.

## Actions
There's two workflows running on this Github repository:

* [YARA-CI](https://yara-ci.cloud.virustotal.com/): runs automatically to detect signature errors, as well as false positives and false negatives.
* [Package Yara rules](https://github.com/bartblaze/Yara-rules/blob/master/.github/workflows/yara.yml): allows download of a complete rules file (all Yara rules from this repo in one file) for convenience from the Actions tab > Choose the last workflow run > Artifacts. Scroll down and you will be able to download, but you must be logged in to Github:

![image](https://github.com/user-attachments/assets/904aa2af-8b91-4c01-97b4-db24f9659005)


[![Package Yara Rules](https://github.com/bartblaze/Yara-rules/actions/workflows/yara.yml/badge.svg)](https://github.com/bartblaze/Yara-rules/actions/workflows/yara.yml)

## Minimum Yara version needed?
**v3.3.0** is minimally needed, as some rules may require a specific module. Note that it's recommended to always use the latest Yara version as found [here](https://github.com/VirusTotal/yara/releases). Yara 4.5.5, likely the last release to be available, works without issue.

## Do the rules work with YARA-X?
[Yara-X](https://github.com/VirusTotal/yara-x), a rewrite of Yara in Rust, has no difficulty running the rules in this repo. At time of writing, YARA-X v1.x and above works fine with the rules presented here.

## Feedback?
If you spot an issue or improvement with one of the rules, feel free to submit a PR or open an Issue.

# Extra

## What is Yara?
From the official Github repo, https://github.com/VirusTotal/yara:
> YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples.

More information: https://yara.readthedocs.io/en/stable/index.html

## What is TLP?
> The Traffic Light Protocol (TLP) was created in order to facilitate greater sharing of information.

The rules in this repo are TLP:CLEAR (TLP:CLEAR was previously known as TLP:WHITE).
> Recipients may share this information without restriction. Information is subject to standard copyright rules.

More information: https://www.us-cert.gov/tlp

## Where can I find other open-source Yara rules?
InQuest has made a Github repo which contains a curated list of Yara rules: https://github.com/InQuest/awesome-yara.
