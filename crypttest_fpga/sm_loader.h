#ifndef _SM_LOADER_H
#define _SM_LOADER_H

#include <sancus/sm_crypt.h>
#include <sancus/sm_support.h>

extern struct SancusModule sm_loader;

int  SM_ENTRY("sm_loader") sm_loader_load(struct SancusCryptModule *scm);
void SM_ENTRY("sm_loader") sm_loader_destroy(void);

#endif /* _SM_LOADER_H */
