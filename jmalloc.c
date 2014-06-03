/*
 * Copyright (c) 2013 - 2014, Liexusong <280259971@qq.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int size;
} jhttp_mem_head;

static volatile int __jmalloc_usage_total = 0;


/*
 * replace malloc(int size);
 */
void *jmalloc(int size)
{
    jhttp_mem_head *m;

    m = malloc(size + sizeof(jhttp_mem_head));
    if (m == NULL) {
        return NULL;
    }

    __sync_fetch_and_add(&__jmalloc_usage_total, size);

    m->size = size;

    return (void *)((char *)m + sizeof(jhttp_mem_head));
}

/*
 * replace realloc(void *ptr, int size);
 */
void *jrealloc(void *ptr, int nsize)
{
    jhttp_mem_head *m = (jhttp_mem_head *)((char *)ptr - sizeof(jhttp_mem_head));
    int osize = m->size;

    m = realloc(m, nsize + sizeof(jhttp_mem_head));
    if (m == NULL) {
        return NULL;
    }

    __sync_fetch_and_sub(&__jmalloc_usage_total, osize);
    __sync_fetch_and_add(&__jmalloc_usage_total, nsize);

    m->size = nsize;

    return (void *)((char *)m + sizeof(jhttp_mem_head));
}

/*
 * replace free(void *ptr);
 */
void jfree(void *ptr)
{
    jhttp_mem_head *m = (jhttp_mem_head *)((char *)ptr - sizeof(jhttp_mem_head));

    __sync_fetch_and_sub(&__jmalloc_usage_total, m->size);

    free((void *)m);
}

int jmalloc_usage_memory()
{
    return __jmalloc_usage_total;
}

