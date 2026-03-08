/*
 * getopt.h — Minimal getopt/getopt_long for MSVC
 */
#ifndef COMPAT_GETOPT_H
#define COMPAT_GETOPT_H

#ifdef _MSC_VER

#ifdef __cplusplus
extern "C" {
#endif

#define no_argument        0
#define required_argument  1
#define optional_argument  2

struct option {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

int getopt(int argc, char *const argv[], const char *optstring);
int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif /* _MSC_VER */

#endif /* COMPAT_GETOPT_H */
