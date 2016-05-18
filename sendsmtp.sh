#!/bin/bash

# Usage: sendsmtp.sh <recipient> <mail>

TO=$1
MAIL=`cat $2`

SMTPCOMMANDS="HELO localhost
MAIL FROM: test
RCPT TO: $TO
DATA
$MAIL
.
"

echo "$SMTPCOMMANDS" | telnet localhost 25
