.PHONY: all build clean

all: build

build:
	@ cd libheap && $(MAKE)
	@ perl scripts/dumplibheap.pl
	@ cd api && $(MAKE)
	@ cd tools && $(MAKE)
	@ cp tools/rop-tool .
clean:
	@ cd libheap && $(MAKE) clean
	@ cd api && $(MAKE) clean
	@ cd tools && $(MAKE) clean
	@ rm -f rop-tool
	find . -name "*~" -delete
