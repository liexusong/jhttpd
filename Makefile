all:
	gcc jhttpd.c jk_hash.c jk_thread_pool.c -o jhttpd -lpthread
