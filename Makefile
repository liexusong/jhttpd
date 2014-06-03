all:
	gcc jhttpd.c jk_hash.c jk_thread_pool.c jmalloc.c -o jhttpd -lpthread -g
