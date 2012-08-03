include $(top_srcdir)/Make_global.am
lib_LTLIBRARIES = libnftables.la

libnftables_la_LIBADD = ${LIBMNL_LIBS}
libnftables_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libnftables.map \
			 -version-info $(LIBVERSION)
libnftables_la_SOURCES = table.c		\
			 chain.c		\
			 rule.c			\
			 expr.c			\
			 expr_ops.c		\
			 expr/cmp.c		\
			 expr/counter.c		\
			 expr/data_reg.c	\
			 expr/immediate.c	\
			 expr/match.c		\
			 expr/meta.c		\
			 expr/payload.c		\
			 expr/target.c		\
			 libnftables.map	\
			 internal.h
