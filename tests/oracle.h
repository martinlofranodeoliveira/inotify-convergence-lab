#ifndef ORACLE_H
#define ORACLE_H
#include "icl.h"
int oracle_check(icl *lab);
int oracle_content(icl *lab, const char *path, const void *expected, size_t length);
#endif
