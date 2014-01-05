#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include <libmnl/libmnl.h> /*nlmsghdr*/
#include <libnftables/ruleset.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/rule.h>
#include <libnftables/set.h>

#ifdef XML_PARSING
#include <mxml.h>
#endif

#ifdef JSON_PARSING
#include <jansson.h>
#endif

enum {
	TEST_XML_TABLE = 0,
	TEST_XML_CHAIN,
	TEST_XML_RULE,
	TEST_XML_SET,
	TEST_XML_RULESET,
	TEST_JSON_TABLE,
	TEST_JSON_CHAIN,
	TEST_JSON_RULE,
	TEST_JSON_SET,
	TEST_JSON_RULESET,
};

#if defined(XML_PARSING) || defined(JSON_PARSING)
static void print_detail_error(char *a, char *b)
{
	int i;
	int from = -1;

	for (i = 0; i < strlen(b); i++) {
		if (from == -1 && a[i] != b[i]) {
			from = i;
			break;

		}
	}

	if (from != -1) {
		int k = from - 10;

		if (k < 0)
			k = 0;

		fprintf(stderr, "from file:     ");
		for (i = k; i < from + 10; i++)
			fprintf(stderr, "%c", a[i]);

		fprintf(stderr, "\nfrom snprintf: ");
		for (i = k; i < from + 10; i++)
			fprintf(stderr, "%c", b[i]);

		/* Don't look twice below this comment ;-) */
		fprintf(stderr, "\n               ");
		for (i = k; i < from + 10; i++) {
			if (i == from)
				fprintf(stderr, "^");
			else
				fprintf(stderr, " ");
		}
		fprintf(stderr, "\n");
	}
}

static int compare_test(uint32_t type, void *input, const char *filename)
{
	struct nft_table *t = NULL;
	struct nft_chain *c = NULL;
	struct nft_rule *r = NULL;
	struct nft_set *s = NULL;
	struct nft_ruleset *rs = NULL;
	char orig[4096];
	char out[4096];
	FILE *fp;

	switch (type) {
	case TEST_XML_TABLE:
	case TEST_JSON_TABLE:
		t = (struct nft_table *)input;
		break;
	case TEST_XML_CHAIN:
	case TEST_JSON_CHAIN:
		c = (struct nft_chain *)input;
		break;
	case TEST_XML_RULE:
	case TEST_JSON_RULE:
		r = (struct nft_rule *)input;
		break;
	case TEST_XML_SET:
	case TEST_JSON_SET:
		s = (struct nft_set *)input;
		break;
	case TEST_XML_RULESET:
	case TEST_JSON_RULESET:
		rs = (struct nft_ruleset *)input;
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	switch (type) {
	case TEST_XML_TABLE:
		nft_table_snprintf(out, sizeof(out), t, NFT_OUTPUT_XML, 0);
		break;
	case TEST_JSON_TABLE:
		nft_table_snprintf(out, sizeof(out), t, NFT_OUTPUT_JSON, 0);
		break;
	case TEST_XML_CHAIN:
		nft_chain_snprintf(out, sizeof(out), c, NFT_OUTPUT_XML, 0);
		break;
	case TEST_JSON_CHAIN:
		nft_chain_snprintf(out, sizeof(out), c, NFT_OUTPUT_JSON, 0);
		break;
	case TEST_XML_RULE:
		nft_rule_snprintf(out, sizeof(out), r, NFT_OUTPUT_XML, 0);
		break;
	case TEST_JSON_RULE:
		nft_rule_snprintf(out, sizeof(out), r, NFT_OUTPUT_JSON, 0);
		break;
	case TEST_XML_SET:
		nft_set_snprintf(out, sizeof(out), s, NFT_OUTPUT_XML, 0);
		break;
	case TEST_JSON_SET:
		nft_set_snprintf(out, sizeof(out), s, NFT_OUTPUT_JSON, 0);
		break;
	case TEST_XML_RULESET:
		nft_ruleset_snprintf(out, sizeof(out), rs,
				     NFT_OUTPUT_XML, 0);
		break;
	case TEST_JSON_RULESET:
		nft_ruleset_snprintf(out, sizeof(out), rs,
				     NFT_OUTPUT_JSON, 0);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	fgets(orig, sizeof(orig), fp);
	fclose(fp);

	if (strncmp(orig, out, strlen(out)) == 0)
		return 0;

	printf("validating %s: ", filename);
	printf("\033[31mFAILED\e[0m\n");
	print_detail_error(orig, out);
	return -1;
}
#endif

static int test_json(const char *filename, struct nft_parse_err *err)
{
#ifdef JSON_PARSING
	int ret = -1;
	struct nft_table *t;
	struct nft_chain *c;
	struct nft_rule *r;
	struct nft_set *s;
	struct nft_ruleset *rs;
	json_t *root;
	json_error_t error;
	char *json;

	root = json_load_file(filename, 0, &error);
	if (!root)
		return -1;

	json = json_dumps(root, JSON_INDENT(0));

	if (json_object_get(root, "table") != NULL) {
		t = nft_table_alloc();
		if (t != NULL) {
			if (nft_table_parse(t, NFT_PARSE_JSON, json, err) == 0)
				ret = compare_test(TEST_JSON_TABLE, t, filename);
			else
				goto failparsing;

			nft_table_free(t);
		}
	} else if (json_object_get(root, "chain") != NULL) {
		c = nft_chain_alloc();
		if (c != NULL) {
			if (nft_chain_parse(c, NFT_PARSE_JSON, json, err) == 0)
				ret = compare_test(TEST_JSON_CHAIN, c, filename);
			else
				goto failparsing;

			nft_chain_free(c);
		}
	} else if (json_object_get(root, "rule") != NULL) {
		r = nft_rule_alloc();
		if (r != NULL) {
			if (nft_rule_parse(r, NFT_PARSE_JSON, json, err) == 0)
				ret = compare_test(TEST_JSON_RULE, r, filename);
			else
				goto failparsing;

			nft_rule_free(r);
		}
	} else if (json_object_get(root, "set") != NULL) {
		s = nft_set_alloc();
		if (s != NULL) {
			if (nft_set_parse(s, NFT_PARSE_JSON, json, err) == 0)
				ret = compare_test(TEST_JSON_SET, s, filename);
			else
				goto failparsing;

			nft_set_free(s);
			}
	} else if (json_object_get(root, "nftables") != NULL) {
		rs = nft_ruleset_alloc();
		if (rs != NULL) {
			if (nft_ruleset_parse(rs, NFT_PARSE_JSON, json, err) == 0)
				ret = compare_test(TEST_JSON_RULESET, rs, filename);
			else
				goto failparsing;

			nft_ruleset_free(rs);
			}
	}

	free(json);
	json_decref(root);
	return ret;

failparsing:
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	free(json);
	json_decref(root);
	return -1;
#else
	printf("Compiled without support for JSON.\n");
	return -1;
#endif
}

static int test_xml(const char *filename, struct nft_parse_err *err)
{
#ifdef XML_PARSING
	int ret = -1;
	struct nft_table *t;
	struct nft_chain *c;
	struct nft_rule *r;
	struct nft_set *s;
	struct nft_ruleset *rs;
	FILE *fp;
	mxml_node_t *tree;
	char *xml;

	fp = fopen(filename, "r");
	tree = mxmlLoadFile(NULL, fp, MXML_NO_CALLBACK);
	fclose(fp);

	if (tree == NULL) {
		printf("unable to build XML tree from file "
		       "%s \033[31mFAILED\e[0m\n", filename);
		return -1;
	}

	xml = mxmlSaveAllocString(tree, MXML_NO_CALLBACK);
	if (xml == NULL) {
		printf("unable to alloc string from XML tree from %s "
		       "\033[31mFAILED\e[0m\n", filename);
		return -1;
	}

	/* Check what parsing should be done */
	if (strcmp(tree->value.opaque, "table") == 0) {
		t = nft_table_alloc();
		if (t != NULL) {
			if (nft_table_parse(t, NFT_PARSE_XML, xml, err) == 0)
				ret = compare_test(TEST_XML_TABLE, t, filename);
			else
				goto failparsing;

			nft_table_free(t);
		}
	} else if (strcmp(tree->value.opaque, "chain") == 0) {
		c = nft_chain_alloc();
		if (c != NULL) {
			if (nft_chain_parse(c, NFT_PARSE_XML, xml, err) == 0)
				ret = compare_test(TEST_XML_CHAIN, c, filename);
			else
				goto failparsing;

			nft_chain_free(c);
		}
	} else if (strcmp(tree->value.opaque, "rule") == 0) {
		r = nft_rule_alloc();
		if (r != NULL) {
			if (nft_rule_parse(r, NFT_PARSE_XML, xml, err) == 0)
				ret = compare_test(TEST_XML_RULE, r, filename);
			else
				goto failparsing;

			nft_rule_free(r);
		}
	} else if (strcmp(tree->value.opaque, "set") == 0) {
		s = nft_set_alloc();
		if (s != NULL) {
			if (nft_set_parse(s, NFT_PARSE_XML, xml, err) == 0)
				ret = compare_test(TEST_XML_SET, s, filename);
			else
				goto failparsing;

			nft_set_free(s);
		}
	} else if (strcmp(tree->value.opaque, "nftables") == 0) {
		rs = nft_ruleset_alloc();
		if (rs != NULL) {
			if (nft_ruleset_parse(rs, NFT_PARSE_XML,
					      xml, err) == 0)
				ret = compare_test(TEST_XML_RULESET, rs,
						   filename);
			else
				goto failparsing;

			nft_ruleset_free(rs);
		}
	}

	mxmlDelete(tree);
	return ret;

failparsing:
	mxmlDelete(tree);
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	return -1;
#else
	printf("Compiled without support for XML.\n");
	return -1;
#endif
}

int main(int argc, char *argv[])
{
	DIR *d;
	struct dirent *dent;
	char path[PATH_MAX];
	int ret = 0, exit_code = 0;
	struct nft_parse_err *err;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	d = opendir(argv[1]);
	if (d == NULL) {
		perror("opendir");
		exit(EXIT_FAILURE);
	}

	err = nft_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	while ((dent = readdir(d)) != NULL) {
		int len = strlen(dent->d_name);

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", argv[1], dent->d_name);

		if (strcmp(&dent->d_name[len-4], ".xml") == 0) {
			if ((ret = test_xml(path, err)) == 0) {
				printf("parsing and validating %s: ", path);
				printf("\033[32mOK\e[0m\n");
			}
			exit_code += ret;
		}
		if (strcmp(&dent->d_name[len-5], ".json") == 0) {
			if ((ret = test_json(path, err)) == 0) {
				printf("parsing and validating %s: ", path);
				printf("\033[32mOK\e[0m\n");
			}
			exit_code += ret;
		}
	}

	closedir(d);
	nft_parse_err_free(err);

	if (exit_code != 0)
		exit(EXIT_FAILURE);

	return 0;
}
