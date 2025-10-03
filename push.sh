#!/usr/bin/bash

# Remove duplicate lines
awk '!a[$0]++' blacklist.txt > blacklist.new
mv blacklist.new blacklist.txt

# Stage text files
git add *.txt

# Check if there are any changes to commit
if git diff --cached --quiet -- '*.txt'; then
    echo "No changes to commit. Exiting."
    exit 0
fi

# Commit and push
git commit -m "$(date '+%A %B %d %I:%M %p %Y')"
git push origin main

