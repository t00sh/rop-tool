#include "ropc.h"

enum BINFMT_ERR raw_load(BINFMT *bin) {
  bin->mlist = mlist_new();

  mlist_add(bin->mlist,
	    0,
	    bin->mapped,
	    bin->mapped_size,
	    MEM_FLAG_PROT_X | MEM_FLAG_PROT_R | MEM_FLAG_PROT_X);

  bin->type = BINFMT_TYPE_RAW;
  bin->arch = BINFMT_ARCH_X86;
  bin->endian = BINFMT_ENDIAN_LITTLE;

  return BINFMT_ERR_OK;
}
