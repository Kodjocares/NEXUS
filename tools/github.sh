#!/bin/bash
# NEXUS — GitHub dev automation (see full implementation in session history)
INPUT="$1"
if echo "$INPUT" | grep -qi "pr"; then
  gh pr list --json title,url,state --template '{{range .}}• {{.title}} → {{.url}}{{"\n"}}{{end}}'
elif echo "$INPUT" | grep -qi "issue"; then
  gh issue list --json title,url --template '{{range .}}• {{.title}} → {{.url}}{{"\n"}}{{end}}'
fi
