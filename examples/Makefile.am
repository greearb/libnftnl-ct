include $(top_srcdir)/Make_global.am

check_PROGRAMS = nft-table-add		\
		 nft-table-upd		\
		 nft-table-del		\
		 nft-table-get		\
		 nft-chain-add		\
		 nft-chain-del		\
		 nft-chain-get		\
		 nft-rule-add		\
		 nft-rule-del		\
		 nft-rule-get		\
		 nft-events		\
		 nft-compat-get

nft_table_add_SOURCES = nft-table-add.c
nft_table_add_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_table_upd_SOURCES = nft-table-upd.c
nft_table_upd_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_table_del_SOURCES = nft-table-del.c
nft_table_del_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_table_get_SOURCES = nft-table-get.c
nft_table_get_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_chain_add_SOURCES = nft-chain-add.c
nft_chain_add_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_chain_del_SOURCES = nft-chain-del.c
nft_chain_del_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_chain_get_SOURCES = nft-chain-get.c
nft_chain_get_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_rule_add_SOURCES = nft-rule-add.c
nft_rule_add_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_rule_del_SOURCES = nft-rule-del.c
nft_rule_del_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_rule_get_SOURCES = nft-rule-get.c
nft_rule_get_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_events_SOURCES = nft-events.c
nft_events_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}

nft_compat_get_SOURCES = nft-compat-get.c
nft_compat_get_LDADD = ../src/libnftables.la ${LIBMNL_LIBS}
