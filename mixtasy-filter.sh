#!/bin/bash

# Mixtasy shell script filter adapter. It is meant to be invoked as follows:
#       /path/to/mixtasy-filter.sh -f sender -- recipients...

# http://www.postfix.org/FILTER_README.html

# This is the address of the local mixtasy mix
MIXADDRESS="mixtasy@testserver.vm"

# This is the working directory to cache messages
INSPECT_DIR="/var/spool/mixtasy"

# This command is used to inject mails not addressed to the mixtasy mix back to postfix
SENDMAIL="/usr/sbin/sendmail -G -i" # NEVER NEVER NEVER use "-t" here.

# This command is used to inject unpacked mixtasy mix messages to postfix
MIXMAIL="/usr/sbin/sendmail -G -i -t"
# -t is fine here because the next hop is specified in the inner mix message

# This specifies the command to unpack mix messages
PYTHON="/usr/bin/python2.7"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MIXTASY="$PYTHON $DIR/mixtasy.py -u -o"

LOGFILE="/var/log/mixtasy.log"


# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$*" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || {
    echo $INSPECT_DIR does not exist; exit $EX_TEMPFAIL; }

# Save message to file
cat >in.$$ || { 
    echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# Only process as a mixtasy message if addressed to MIXADDRESS
if [[ $4 == $MIXADDRESS ]]; then	
	# Specify your content filter here.
	$MIXTASY in.$$ <in.$$ 2>> $LOGFILE || {
	  echo Message content rejected; exit $EX_UNAVAILABLE; }

	# Re-inject the unpacked mixtasy message...
	$MIXMAIL <in.$$

	exit $?
fi

# Re-inject unaltered mail to postfix...
$SENDMAIL "$@" <in.$$

exit $?
