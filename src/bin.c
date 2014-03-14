#include "ropc.h"

typedef struct BINFMT_LIST {
  const char *name;
  enum BINFMT_ERR (*load)(BINFMT*);
}BINFMT_LIST;

static BINFMT_LIST bin_list[] = {
  {"elf32", elf32_load},
  {"elf64", elf64_load},
  {NULL,    NULL}
};

static const char* bin_get_err(enum BINFMT_ERR err) {
  switch(err) {
  case BINFMT_ERR_OK:
    return "OK";
  case BINFMT_ERR_UNRECOGNIZED:
    return "unrecognized file format";
  case BINFMT_ERR_NOTSUPPORTED:
    return "not yet supported";
  case BINFMT_ERR_MALFORMEDFILE:
    return "malformed file (3vil or offuscated file ?!)";
  }
  return "Unknown error";
}

static void bin_check(BINFMT *bin) {
  if(bin->endian == BINFMT_ENDIAN_UNDEF)
    FATAL_ERROR("Endianess not supported");

  if(bin->arch == BINFMT_ARCH_UNDEF)
    FATAL_ERROR("Arch not supported");

  if(bin->type == BINFMT_TYPE_UNDEF)
    FATAL_ERROR("File format not recognized");
}

void bin_load(BINFMT *bin, const char *filename) {
  struct stat st;
  int i, fd;
  enum BINFMT_ERR err;

  fd = xopen(filename, O_RDONLY);  
  xfstat(fd, &st);

  bin->mapped = xmmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  bin->mapped_size = st.st_size;

  for(i = 0; bin_list[i].load != NULL; i++) {
    err = bin_list[i].load(bin);
    DEBUG("Try to load %s -> %d", bin_list[i].name, err);
    if(err == BINFMT_ERR_OK) {
      bin_check(bin);
      return;
    }
    if(err != BINFMT_ERR_UNRECOGNIZED)
      FATAL_ERROR("Error in %s loader : %s", bin_list[i].name, bin_get_err(err));
  }
  FATAL_ERROR("Format not supported");
}

void bin_free(BINFMT *bin) {
  mlist_free(&bin->mlist);
  munmap(bin->mapped, bin->mapped_size);
}
