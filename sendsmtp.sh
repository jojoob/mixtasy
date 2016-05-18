#!/bin/bash

# Usage: sendsmtp.sh <recipient> <mailfile>

TO=$1
MAIL=`cat $2`

SMTPCOMMANDS="HELO localhost
MAIL FROM: test
RCPT TO: $TO
DATA
$MAIL
.
QUIT
"

echo "$SMTPCOMMANDS" | telnet localhost 25
