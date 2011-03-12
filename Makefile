all: main.c
	gcc -o mc-loader main.c -Wl,-rpath,/usr/local/lib -lmemcached -lsasl2 -pthread

verbose: main.c
	gcc -o mc-loader main.c -Wl,-rpath,/usr/local/lib -lmemcached -lsasl2 -D VERBOSE -pthread

debug: main.c
	gcc -o mc-loader main.c -Wl,-rpath,/usr/local/lib -lmemcached -lsasl2 -O0 -gfull -pthread

clean:
	rm -f mc-loader
	rm -rf mc-loader.dSYM
