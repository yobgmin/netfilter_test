netfilter_test : nfqnl_test.c
	gcc -o netfilter_test nfqnl_test.c -lnetfilter_queue
