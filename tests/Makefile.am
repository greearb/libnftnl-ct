include $(top_srcdir)/Make_global.am

check_PROGRAMS = nft-parsing-test

nft_parsing_test_SOURCES = nft-parsing-test.c
nft_parsing_test_LDADD = ../src/libnftables.la ${LIBMNL_LIBS} ${LIBXML_LIBS}
