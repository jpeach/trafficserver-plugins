# If tsxs is not in your path, then change this by running
# make TSXS=/path/to/ts/bin/tsxs target
TSXS?=tsxs

%.so: %.c
	$(TSXS) -c $< -o $@

all: cacheurl.so

install: all
	$(TSXS) -i -o cacheurl.so

clean:
	rm -f *.lo *.so
