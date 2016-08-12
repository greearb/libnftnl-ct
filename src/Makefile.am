include $(top_srcdir)/Make_global.am
lib_LTLIBRARIES = libnftnl.la

libnftnl_la_LIBADD = ${LIBMNL_LIBS} ${LIBXML_LIBS} ${LIBJSON_LIBS}
libnftnl_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnftnl.map	\
		      -version-info $(LIBVERSION)

libnftnl_la_SOURCES = utils.c		\
		      batch.c		\
		      buffer.c		\
		      common.c		\
		      gen.c		\
		      table.c		\
		      trace.c		\
		      chain.c		\
		      rule.c		\
		      set.c		\
		      set_elem.c	\
		      ruleset.c		\
		      mxml.c		\
		      jansson.c		\
		      udata.c		\
		      expr.c		\
		      expr_ops.c	\
		      expr/bitwise.c	\
		      expr/byteorder.c	\
		      expr/cmp.c	\
		      expr/counter.c	\
		      expr/ct.c		\
		      expr/data_reg.c	\
		      expr/dup.c	\
		      expr/exthdr.c	\
		      expr/fwd.c	\
		      expr/limit.c	\
		      expr/log.c	\
		      expr/lookup.c	\
		      expr/dynset.c	\
		      expr/immediate.c	\
		      expr/match.c	\
		      expr/meta.c	\
		      expr/nat.c	\
		      expr/payload.c	\
		      expr/queue.c	\
		      expr/reject.c	\
		      expr/target.c	\
		      expr/masq.c	\
		      expr/redir.c	\
		      expr/hash.c	\
		      libnftnl.map
