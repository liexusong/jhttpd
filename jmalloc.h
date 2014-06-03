#ifndef __JHTTP_MALLOC_H
#define __JHTTP_MALLOC_H

void *jmalloc(int size);
void *jrealloc(void *ptr, int nsize);
void jfree(void *ptr);
int jmalloc_usage_memory();

#endif
