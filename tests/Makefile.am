include $(top_srcdir)/Make_global.am

EXTRA_DIST =		test-script.sh			\
			jsonfiles			\
			xmlfiles

check_PROGRAMS = 	nft-parsing-test		\
			nft-table-test			\
			nft-chain-test			\
			nft-rule-test			\
			nft-set-test			\
			nft-expr_bitwise-test		\
			nft-expr_byteorder-test		\
			nft-expr_counter-test		\
			nft-expr_cmp-test		\
			nft-expr_ct-test		\
			nft-expr_exthdr-test		\
			nft-expr_immediate-test		\
			nft-expr_limit-test		\
			nft-expr_lookup-test		\
			nft-expr_log-test		\
			nft-expr_match-test		\
			nft-expr_masq-test		\
			nft-expr_meta-test		\
			nft-expr_nat-test		\
			nft-expr_payload-test		\
			nft-expr_queue-test		\
			nft-expr_redir-test		\
			nft-expr_reject-test		\
			nft-expr_target-test

nft_parsing_test_SOURCES = nft-parsing-test.c
nft_parsing_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS} ${LIBXML_LIBS} ${LIBJSON_LIBS}

nft_table_test_SOURCES = nft-table-test.c
nft_table_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_chain_test_SOURCES = nft-chain-test.c
nft_chain_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_rule_test_SOURCES = nft-rule-test.c
nft_rule_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_set_test_SOURCES = nft-set-test.c
nft_set_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_bitwise_test_SOURCES = nft-expr_bitwise-test.c
nft_expr_bitwise_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_byteorder_test_SOURCES = nft-expr_byteorder-test.c
nft_expr_byteorder_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_cmp_test_SOURCES = nft-expr_cmp-test.c
nft_expr_cmp_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_counter_test_SOURCES = nft-expr_counter-test.c
nft_expr_counter_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_exthdr_test_SOURCES = nft-expr_exthdr-test.c
nft_expr_exthdr_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_ct_test_SOURCES = nft-expr_ct-test.c
nft_expr_ct_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_immediate_test_SOURCES = nft-expr_counter-test.c
nft_expr_immediate_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_limit_test_SOURCES = nft-expr_limit-test.c
nft_expr_limit_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_lookup_test_SOURCES = nft-expr_limit-test.c
nft_expr_lookup_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_log_test_SOURCES = nft-expr_log-test.c
nft_expr_log_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_match_test_SOURCES = nft-expr_match-test.c
nft_expr_match_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_masq_test_SOURCES = nft-expr_masq-test.c
nft_expr_masq_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_meta_test_SOURCES = nft-expr_meta-test.c
nft_expr_meta_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_nat_test_SOURCES = nft-expr_nat-test.c
nft_expr_nat_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_payload_test_SOURCES = nft-expr_payload-test.c
nft_expr_payload_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_queue_test_SOURCES = nft-expr_queue-test.c
nft_expr_queue_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_reject_test_SOURCES = nft-expr_reject-test.c
nft_expr_reject_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_redir_test_SOURCES = nft-expr_redir-test.c
nft_expr_redir_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}

nft_expr_target_test_SOURCES = nft-expr_target-test.c
nft_expr_target_test_LDADD = ../src/libnftnl.la ${LIBMNL_LIBS}
