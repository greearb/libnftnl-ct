#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include <libmnl/libmnl.h> /*nlmsghdr*/
#include <libnftnl/ruleset.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>

enum {
	TEST_XML_RULESET,
	TEST_JSON_RULESET,
};

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

static int compare_test(uint32_t type, struct nft_ruleset *rs,
			const char *filename, FILE *fp)
{
	char orig[4096];
	char out[4096];

	switch (type) {
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

	rewind(fp);
	fgets(orig, sizeof(orig), fp);

	if (strncmp(orig, out, strlen(out)) == 0)
		return 0;

	printf("validating %s: ", filename);
	printf("\033[31mFAILED\e[0m\n");
	print_detail_error(orig, out);
	return -1;
}

static int test_json(const char *filename, struct nft_parse_err *err)
{
	int ret = -1;
	struct nft_ruleset *rs;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("unable to open file %s: %s\n", filename,
		       strerror(errno));
		return -1;
	}

	rs = nft_ruleset_alloc();
	if (rs == NULL) {
		perror("nft_ruleset_alloc");
		return -1;
	}

	if (nft_ruleset_parse_file(rs, NFT_PARSE_JSON, fp, err) == 0)
		ret = compare_test(TEST_JSON_RULESET, rs, filename, fp);
	else
		goto failparsing;

	nft_ruleset_free(rs);
	fclose(fp);

	return ret;

failparsing:
	fclose(fp);
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	nft_parse_perror("fail", err);
	return -1;
}

static int test_xml(const char *filename, struct nft_parse_err *err)
{
	int ret = -1;
	struct nft_ruleset *rs;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("unable to open file %s: %s\n", filename,
		       strerror(errno));
		return -1;
	}

	rs = nft_ruleset_alloc();
	if (rs == NULL) {
		perror("nft_ruleset_alloc");
		return -1;
	}

	if (nft_ruleset_parse_file(rs, NFT_PARSE_XML, fp, err) == 0)
		ret = compare_test(TEST_XML_RULESET, rs, filename, fp);
	else
		goto failparsing;

	nft_ruleset_free(rs);
	fclose(fp);

	return ret;

failparsing:
	fclose(fp);
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	return -1;
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
