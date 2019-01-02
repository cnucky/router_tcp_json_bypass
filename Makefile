build:
	g++ -gdwarf-2 -o injectcp injectcp.cpp -lnet -lpcap -lpthread
clean:
	rm -rf injectcp
