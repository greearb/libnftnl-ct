#!/bin/bash

#
# (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This is a small testbench for adding nftables rules to kernel
# in XML format.

BINARY="../examples/nft-rule-xml-add"
NFT="$( which nft )"
MKTEMP="$( which mktemp )"
TMPFILE="$( $MKTEMP )"

if [ ! -x "$BINARY" ] ; then
	echo "E: Binary not found $BINARY"
	exit 1
fi

if [ ! -x "$MKTEMP" ] ; then
	echo "E: mktemp not found. Is mandatory."
	exit 1
fi

if [ ! -w "$TMPFILE" ] ; then
	echo "E: Unable to create tempfile with mktemp"
	exit 1
fi

[ ! -x "$NFT" ] && echo "W: nftables main binary not found but continuing anyway $NFT"

XML="<rule family=\"2\" table=\"filter\" chain=\"INPUT\" handle=\"100\" version=\"0\">
  <rule_flags>0</rule_flags>
  <flags>127</flags>
  <compat_flags>0</compat_flags>
  <compat_proto>0</compat_proto>
  <expr type=\"meta\">
    <dreg>1</dreg>
    <key>4</key>
  </expr>
  <expr type=\"cmp\">
    <sreg>1</sreg>
    <op>eq</op>
    <cmpdata>
      <data_reg type=\"value\">
        <len>1</len>
        <data0>0x04000000</data0>
      </data_reg>
    </cmpdata>
  </expr>
  <expr type=\"payload\">
    <dreg>1</dreg>
    <base>1</base>
    <offset>12</offset>
    <len>4</len>
  </expr>
  <expr type=\"cmp\">
    <sreg>1</sreg>
    <op>eq</op>
    <cmpdata>
      <data_reg type=\"value\">
        <len>1</len>
        <data0>0x96d60496</data0>
      </data_reg>
    </cmpdata>
  </expr>
  <expr type=\"payload\">
    <dreg>1</dreg>
    <base>1</base>
    <offset>16</offset>
    <len>4</len>
  </expr>
  <expr type=\"cmp\">
    <sreg>1</sreg>
    <op>eq</op>
    <cmpdata>
      <data_reg type=\"value\">
        <len>1</len>
        <data0>0x96d60329</data0>
      </data_reg>
    </cmpdata>
  </expr>
  <expr type=\"payload\">
    <dreg>1</dreg>
    <base>1</base>
    <offset>9</offset>
    <len>1</len>
  </expr>
  <expr type=\"cmp\">
    <sreg>1</sreg>
    <op>eq</op>
    <cmpdata>
      <data_reg type=\"value\">
        <len>1</len>
        <data0>0x06000000</data0>
      </data_reg>
    </cmpdata>
  </expr>
  <expr type=\"match\">
    <name>state</name>
    <rev>0</rev>
    <info>
    </info>
  </expr>
  <expr type=\"counter\">
    <pkts>123123</pkts>
    <bytes>321321</bytes>
  </expr>
  <expr type=\"target\">
    <name>LOG</name>
    <rev>0</rev>
    <info>
    </info>
  </expr>
</rule>"

$NFT add table filter 2>/dev/null >&2
$NFT add chain filter INPUT 2>/dev/null >&2

echo $XML > $TMPFILE
if ! $BINARY "$TMPFILE" ; then
	echo "E: Unable to add XML."
	rm -rf $TMPFILE 2>/dev/null
	exit 1
fi

rm -rf $TMPFILE 2>/dev/null
echo "I: Test OK"
