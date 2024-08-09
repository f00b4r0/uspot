---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Configuration**
Provide the output of:
- `opkg list-installed | grep uspot`
- `uci show uspot` (replace passwords with XXXX as needed)
- `uci show network`
- `uci show firewall`
- `uci show uhttpd`
- `uci show dhcp`

**Logs**
Please provide the relevant content of `logread` when the problem occurs. Provide a few dozen lines of context output prior to the the actual error messages if any.

**Additional context**
Add any other context about the problem here.
