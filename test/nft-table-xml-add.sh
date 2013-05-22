#!/bin/bash

#
# (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

# This is a small testbench for adding nftables tables to kernel
# in XML format.

BINARY="../examples/nft-table-xml-add"
NFT="$( which nft )"
MKTEMP="$( which mktemp)"
TMPFILE="$( $MKTEMP )"

if [ ! -x "$BINARY" ] ; then
	echo "E: Binary not found $BINARY"
	exit 1
fi

if [ ! -x "$MKTEMP" ] ; then
	echo "E: mktemp not found and is neccesary"
	exit 1
fi

if [ ! -w "$TMPFILE" ] ; then
	echo "E: Unable to create temp file via mktemp"
	exit 1
fi


if [ ! -x "$NFT" ] ; then
	echo "W: nftables main binary not found but continuing anyway $NFT"
fi

# This is valid
XML="<table name=\"filter_test\" version=\"0\">
	<properties>
		<family>2</family>
		<table_flags>0</table_flags>
	</properties>
</table>"

$NFT delete table filter_test 2>/dev/null >&2
echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML:"
	echo "$XML"
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

# This is valid
XML="<table name=\"filter6_test\" version=\"0\">
	<properties>
		<family>10</family>
		<table_flags>0</table_flags>
	</properties>
</table>"

$NFT delete table filter6_test 2>/dev/null >&2
echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML:"
	echo "$XML"
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

rm -rf $TMPFILE 2>/dev/null
echo "I: Test OK"
