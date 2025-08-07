#!/usr/bin/bash

awk '!a[$0]++' blacklist.txt > blacklist.new
mv blacklist.new blacklist.txt

git add *.txt
git commit -m "$(date '+%A %B %d %I:%M %p %Y')"
git push origin main
