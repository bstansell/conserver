#!/bin/sh
# $Id: stamper.sh,v 4.1 91/06/19 14:40:46 ksb Exp $
#
# The outputs a time stamp once an hour (on the hour, we hope).
# We take a list of logfiles to stamp
#
PROGNAME=`basename $0 .sh`
if [ "$#" -eq 0 ]
then
	echo "$PROGNAME: usage files" 1>&2
	exit 1
fi

# sleep until the top of the hour
# output a mark on each log file
# sleep for nearly an hour
while true
do
	(
	IFS="$IFS:"

	# _ Wed Jun 19 14:31:02 EST 1991
	# $1 $2  $3 $4 $5 $6 $7 $8  $9
	set _ `date`

	#sleep `expr 3600 - \( $6 \* 60 + $7 \)`
	)

	mark="[-- MARK -- `date`]"
	for file
	do
		if [ _"-" = _"$file" ]
		then
			echo "$mark"
		else
			echo "$mark" >>$file
		fi
	done

	sleep 3530
done

# NOTREACHED
exit 0
