#ifndef MMDB_H
#define MMDB_H

#include <stddef.h>

typedef struct mmdb_s mmdb;

int  mmdb_open(const char* path, mmdb** out);
void mmdb_close(mmdb* db);
int  mmdb_lookup_country_code(mmdb* db, int family, const void* addr,
                              char* code, size_t code_size);

#endif
