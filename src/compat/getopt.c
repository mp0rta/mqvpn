/*
 * getopt.c — Minimal getopt/getopt_long implementation for MSVC
 */
#ifdef _MSC_VER

#  include "getopt.h"
#  include <string.h>
#  include <stdio.h>

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = '?';

int
getopt(int argc, char *const argv[], const char *optstring)
{
    static int sp = 1;
    int c;
    const char *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }

    optopt = c = argv[optind][sp];
    cp = strchr(optstring, c);
    if (c == ':' || cp == NULL) {
        if (opterr) fprintf(stderr, "unknown option -%c\n", c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    if (cp[1] == ':') {
        if (argv[optind][sp + 1] != '\0') {
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            if (opterr) fprintf(stderr, "option -%c requires an argument\n", c);
            sp = 1;
            return '?';
        } else {
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        optarg = NULL;
    }
    return c;
}

int
getopt_long(int argc, char *const argv[], const char *optstring,
            const struct option *longopts, int *longindex)
{
    if (optind >= argc) return -1;

    /* Handle "--" long options */
    if (argv[optind][0] == '-' && argv[optind][1] == '-') {
        const char *name = argv[optind] + 2;
        if (*name == '\0') {
            optind++;
            return -1;
        }

        /* Find matching long option */
        for (int i = 0; longopts[i].name; i++) {
            size_t nlen = strlen(longopts[i].name);
            if (strncmp(name, longopts[i].name, nlen) == 0 &&
                (name[nlen] == '\0' || name[nlen] == '=')) {
                if (longindex) *longindex = i;
                optind++;

                if (longopts[i].has_arg == required_argument) {
                    if (name[nlen] == '=') {
                        optarg = (char *)&name[nlen + 1];
                    } else if (optind < argc) {
                        optarg = argv[optind++];
                    } else {
                        if (opterr)
                            fprintf(stderr, "option --%s requires an argument\n",
                                    longopts[i].name);
                        return '?';
                    }
                } else if (longopts[i].has_arg == optional_argument) {
                    optarg = (name[nlen] == '=') ? (char *)&name[nlen + 1] : NULL;
                } else {
                    optarg = NULL;
                }

                if (longopts[i].flag) {
                    *longopts[i].flag = longopts[i].val;
                    return 0;
                }
                return longopts[i].val;
            }
        }
        if (opterr) fprintf(stderr, "unknown option %s\n", argv[optind]);
        optind++;
        return '?';
    }

    /* Fall back to short option parsing */
    return getopt(argc, argv, optstring);
}

#endif /* _MSC_VER */
