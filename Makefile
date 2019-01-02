build:
	g++ -gdwarf-2 -o injectcp injectcp.cpp /usr/local/lib/libnet.a /usr/local/lib/libpcap.a -lpthread
clean:
	rm -rf injectcp