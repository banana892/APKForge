#!/bin/bash
# snapshot of temp-space APKForge workspaces
echo "tmp/apkforge entries: $(ls /tmp/apkforge 2>/dev/null | wc -l)"
echo "/tmp/apkforge_* : $(ls -d /tmp/apkforge_* 2>/dev/null | wc -l)"
echo "/tmp apkforge_mod_* : $(ls -d /tmp/apkforge_mod_* 2>/dev/null | wc -l)"
echo "/tmp APKTOOL*.tmp : $(ls -d /tmp/APKTOOL*.tmp 2>/dev/null | wc -l)"
echo "/tmp total entries: $(ls -A /tmp | wc -l)"
