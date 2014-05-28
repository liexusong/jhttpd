/*
 * Copyright (c) 2012 - 2013, Liexusong <280259971@qq.com>
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

#ifndef __JK_THREAD_POOL_H
#define __JK_THREAD_POOL_H

#include <pthread.h>

typedef void jk_thread_call_fn(void *);
typedef void jk_thread_finish_fn(void *);
typedef struct jk_thread_task_s jk_thread_task_t;

typedef struct jk_thread_pool_s {
    int worker_threads;
    pthread_t *tids;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int wait_threads;
    pthread_mutex_t wait_lock;
    pthread_cond_t wait_cond;
    jk_thread_task_t *tasks;
    int task_nums;
    int quit_flag;
} jk_thread_pool_t;

struct jk_thread_task_s {
    jk_thread_call_fn *call;
    jk_thread_finish_fn *finish;
    void *arg;
    jk_thread_task_t *next;
};

jk_thread_pool_t *jk_thread_pool_new(int thread_nums);
int jk_thread_pool_push(jk_thread_pool_t *thd, jk_thread_call_fn *call,
    void *arg, jk_thread_finish_fn *finish);
void jk_thread_pool_destroy(jk_thread_pool_t *thd);


#endif
