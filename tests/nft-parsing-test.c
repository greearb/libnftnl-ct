#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include <libmnl/libmnl.h> /*nlmsghdr*/
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/rule.h>

#ifdef XML_PARSING
#include <mxml.h>
#endif

static int test_xml(const char *filename)
{
#ifdef XML_PARSING
	int ret = -1;
	struct nft_table *t = NULL;
	struct nft_chain *c = NULL;
	struct nft_rule *r = NULL;
	FILE *fp;
	mxml_node_t *tree = NULL;;
	char *xml = NULL;

	fp = fopen(filename, "r");
	tree = mxmlLoadFile(NULL, fp, MXML_NO_CALLBACK);
	fclose(fp);

	if (tree == NULL)
		return -1;

	xml = mxmlSaveAllocString(tree, MXML_NO_CALLBACK);
	if (xml == NULL)
		return -1;

	/* Check what parsing should be done */
	if (strcmp(tree->value.opaque, "table") == 0) {
		t = nft_table_alloc();
		if (t != NULL) {
			if (nft_table_parse(t, NFT_TABLE_PARSE_XML, xml) == 0)
				ret = 0;

			nft_table_free(t);
		}
	} else if (strcmp(tree->value.opaque, "chain") == 0) {
		c = nft_chain_alloc();
		if (c != NULL) {
			if (nft_chain_parse(c, NFT_CHAIN_PARSE_XML, xml) == 0)
				ret = 0;

			nft_chain_free(c);
		}
	} else if (strcmp(tree->value.opaque, "rule") == 0) {
		r = nft_rule_alloc();
		if (r != NULL) {
			if (nft_rule_parse(r, NFT_RULE_PARSE_XML, xml) == 0)
				ret = 0;

			nft_rule_free(r);
		}
	}

	return ret;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

int main(int argc, char *argv[])
{
	DIR *d;
	struct dirent *dent;
	char path[PATH_MAX];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	d = opendir(argv[1]);
	if (d == NULL) {
		perror("opendir");
		exit(EXIT_FAILURE);
	}

	while ((dent = readdir(d)) != NULL) {
		int len = strlen(dent->d_name);

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", argv[1], dent->d_name);

		if (strcmp(&dent->d_name[len-4], ".xml") == 0) {
			printf("parsing %s: ", path);
			if (test_xml(path) < 0)
				printf("\033[31mFAILED\e[0m (%s)\n",
					strerror(errno));
			else
				printf("\033[32mOK\e[0m\n");
		}
	}

	closedir(d);
	return 0;
}
