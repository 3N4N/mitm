all:
	$(MAKE) -C spoofer/
	$(MAKE) -C sniffer/

clean:
	$(MAKE) clean -C spoofer/
	$(MAKE) clean -C sniffer/
