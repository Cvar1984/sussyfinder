#!/usr/bin/bash
while read -r line; do
  grep "$line" blacklist.txt
done < whitelist.txt

