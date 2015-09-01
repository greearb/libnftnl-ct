#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>

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

static bool update = false;

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

static int compare_test(uint32_t type, struct nftnl_ruleset *rs,
			const char *filename, FILE *fp)
{
	char orig[4096];
	char out[4096];

	switch (type) {
	case TEST_XML_RULESET:
		nftnl_ruleset_snprintf(out, sizeof(out), rs,
				     NFTNL_OUTPUT_XML, NFTNL_OF_EVENT_NEW);
		break;
	case TEST_JSON_RULESET:
		nftnl_ruleset_snprintf(out, sizeof(out), rs,
				     NFTNL_OUTPUT_JSON, NFTNL_OF_EVENT_NEW);
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	rewind(fp);
	fgets(orig, sizeof(orig), fp);

	if (strncmp(orig, out, strlen(out)) == 0) {
		if (update)
			printf("%s: No changes to update\n", filename);
		return 0;
	}
	if (update) {
		FILE *fout;
		printf("%s: Updating test file\n", filename);
		fout = fopen(filename, "w");
		if (fout == NULL) {
			printf("unable to open file %s: %s\n", filename,
			strerror(errno));
			return -1;
		}
		fprintf(fout, "%s\n", out);
		fclose(fout);
		return 0;
	}

	printf("validating %s: ", filename);
	printf("\033[31mFAILED\e[0m\n");
	print_detail_error(orig, out);
	return -1;
}

static int test_json(const char *filename, struct nftnl_parse_err *err)
{
	int ret = -1;
	struct nftnl_ruleset *rs;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("unable to open file %s: %s\n", filename,
		       strerror(errno));
		return -1;
	}

	rs = nftnl_ruleset_alloc();
	if (rs == NULL) {
		perror("nftnl_ruleset_alloc");
		return -1;
	}

	if (nftnl_ruleset_parse_file(rs, NFTNL_PARSE_JSON, fp, err) == 0)
		ret = compare_test(TEST_JSON_RULESET, rs, filename, fp);
	else
		goto failparsing;

	nftnl_ruleset_free(rs);
	fclose(fp);

	return ret;

failparsing:
	fclose(fp);
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	nftnl_parse_perror("Reason", err);
	return -1;
}

static int test_xml(const char *filename, struct nftnl_parse_err *err)
{
	int ret = -1;
	struct nftnl_ruleset *rs;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("unable to open file %s: %s\n", filename,
		       strerror(errno));
		return -1;
	}

	rs = nftnl_ruleset_alloc();
	if (rs == NULL) {
		perror("nftnl_ruleset_alloc");
		return -1;
	}

	if (nftnl_ruleset_parse_file(rs, NFTNL_PARSE_XML, fp, err) == 0)
		ret = compare_test(TEST_XML_RULESET, rs, filename, fp);
	else
		goto failparsing;

	nftnl_ruleset_free(rs);
	fclose(fp);

	return ret;

failparsing:
	fclose(fp);
	printf("parsing %s: ", filename);
	printf("\033[31mFAILED\e[0m (%s)\n", strerror(errno));
	nftnl_parse_perror("Reason", err);
	return -1;
}

static int execute_test(const char *dir_name)
{
	DIR *d;
	struct dirent *dent;
	char path[PATH_MAX];
	int ret = 0, exit_code = 0;
	struct nftnl_parse_err *err;

	d = opendir(dir_name);
	if (d == NULL) {
		perror("opendir");
		exit(EXIT_FAILURE);
	}

	err = nftnl_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	while ((dent = readdir(d)) != NULL) {
		int len = strlen(dent->d_name);

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_name, dent->d_name);

		if (strcmp(&dent->d_name[len-4], ".xml") == 0) {
			if ((ret = test_xml(path, err)) == 0) {
				if (!update) {
					printf("parsing and validating %s: ",
					       path);
					printf("\033[32mOK\e[0m\n");
				}
			}
			exit_code += ret;
		}
		if (strcmp(&dent->d_name[len-5], ".json") == 0) {
			if ((ret = test_json(path, err)) == 0) {
				if (!update) {
					printf("parsing and validating %s: ",
					       path);
					printf("\033[32mOK\e[0m\n");
				}
			}
			exit_code += ret;
		}
	}

	closedir(d);
	nftnl_parse_err_free(err);

	if (exit_code != 0)
		exit(EXIT_FAILURE);

	return 0;
}

static int execute_test_file(const char *filename)
{
	char path[PATH_MAX];
	int ret = 0;
	struct nftnl_parse_err *err;

	err = nftnl_parse_err_alloc();
	if (err == NULL) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	snprintf(path, sizeof(path), "%s", filename);

	int len = strlen(filename);
	if (strcmp(&filename[len-4], ".xml") == 0) {
		if ((ret = test_xml(path, err)) == 0) {
			if (!update) {
				printf("parsing and validating %s: ",
				       path);
				printf("\033[32mOK\e[0m\n");
			}
		}
		nftnl_parse_err_free(err);
		exit(EXIT_FAILURE);
	}
	if (strcmp(&filename[len-5], ".json") == 0) {
		if ((ret = test_json(path, err)) == 0) {
			if (!update) {
				printf("parsing and validating %s: ",
				       path);
				printf("\033[32mOK\e[0m\n");
			}
		}
		nftnl_parse_err_free(err);
		exit(EXIT_FAILURE);
	}

	nftnl_parse_err_free(err);

	return 0;
}

static void show_help(const char *name)
{
	printf(
"Usage: %s [option]\n"
"\n"
"Options:\n"
"  -d/--dir <directory>		Check test files from <directory>.\n"
"  -u/--update <directory>	Update test files from <directory>.\n"
"  -f/--file <file>		Check test file <file>\n"
"\n",
	       name);
}

int main(int argc, char *argv[])
{
	int val;
	int ret = 0;
	int option_index = 0;
	static struct option long_options[] = {
		{ "dir", required_argument, 0, 'd' },
		{ "update", required_argument, 0, 'u' },
		{ "file", required_argument, 0, 'f' },
		{ 0 }
	};

	if (argc != 3) {
		show_help(argv[0]);
		exit(EXIT_FAILURE);
	}

	while (1) {
		val = getopt_long(argc, argv, "d:u:f:", long_options,
				  &option_index);

		if (val == -1)
			break;

		switch (val) {
		case 'd':
			ret = execute_test(optarg);
			break;
		case 'u':
			update = true;
			ret = execute_test(optarg);
			break;
		case 'f':
			ret = execute_test_file(optarg);
			break;
		default:
			show_help(argv[0]);
			break;
		}
	}
	return ret;
}
