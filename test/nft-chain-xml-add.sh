#!/bin/bash

#
# (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#

# This is a small testbench for adding nftables chains to kernel
# in XML format.

BINARY="../examples/nft-chain-xml-add"
NFT=$( which nft )
MKTEMP=$( which mktemp)
TMPFILE=$( $MKTEMP )

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

[ ! -x "$NFT" ] && echo "W: nftables main binary not found but continuing anyway $NFT"

XML="<chain name=\"test1\" handle=\"100\" bytes=\"123\" packets=\"321\" version=\"0\">
        <properties>
                <type>filter</type>
                <table>filter</table>
                <prio>0</prio>
                <use>0</use>
                <hooknum>NF_INET_LOCAL_IN</hooknum>
                <policy>accept</policy>
                <family>ip</family>
        </properties>
</chain>"

$NFT delete chain ip filter test1 2>/dev/null >&2
echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML:"
	echo "$XML"
	exit 1
fi

# This is valid (as long as the table exist)
XML="<chain name=\"test2\" handle=\"101\" bytes=\"59\" packets=\"1\" version=\"0\">
	<properties>
		<type>filter</type>
		<table>filter</table>
		<prio>1</prio>
		<use>0</use>
		<hooknum>NF_INET_POST_ROUTING</hooknum>
		<policy>accept</policy>
		<family>ip6</family>
	</properties>
</chain>"

$NFT delete chain ip6 filter test2 2>/dev/null >&2
echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML:"
	echo "$XML"
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

# This is valid (as long as the table exist)
XML="<chain name=\"test3\" handle=\"102\" bytes=\"51231239\" packets=\"1123123123\" version=\"0\">
	<properties>
		<type>filter</type>
		<table>filter</table>
		<prio>0</prio>
		<use>0</use>
		<hooknum>NF_INET_FORWARD</hooknum>
		<policy>drop</policy>
		<family>ip</family>
	</properties>
</chain>"

$NFT delete chain ip6 filter test3 2>/dev/null >&2
echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML:"
	echo "$XML"
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

# This is invalid
XML="<chain name=\"XXXX\" handle=\"XXXX\" bytes=\"XXXXXXX\" packets=\"XXXXXXX\" >
		<properties>
			<flags>asdasd</flags>
			<type>filter</type>
			<table>filter</table>
			<prio>asdasd</prio>
			<use>asdasd</use>
			<hooknum>asdasd</hooknum>
			<policy>asdasd</policy>
			<family>asdasd</family>
		</properties>
	</chain>"

if $BINARY "$XML" 2>/dev/null; then
	echo "E: Accepted invalid XML:"
	echo "$XML"
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

rm -rf $TMPFILE 2>/dev/null
echo "I: Test OK"
