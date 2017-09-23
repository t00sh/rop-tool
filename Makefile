.PHONY: all build clean

all: build

build:
	@ cd libheap && $(MAKE)
	@ perl scripts/dumplibheap.pl
	@ cd api && $(MAKE)
	@ cd rop-tool && $(MAKE)

clean:
	@ cd libheap && $(MAKE) clean
	@ cd api && $(MAKE) clean
	@ cd rop-tool && $(MAKE) clean
	find . -name "*~" -delete
