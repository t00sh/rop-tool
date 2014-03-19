#include "ropc.h"

uint64_t endian_get64(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint64_t)p[0] << 56 |
	    (uint64_t)p[1] << 48 |
	    (uint64_t)p[2] << 40 |
	    (uint64_t)p[3] << 32 |
	    (uint64_t)p[4] << 24 |
	    (uint64_t)p[5] << 16 |
	    (uint64_t)p[6] << 8  |
	    (uint64_t)p[7]);

  return ((uint64_t)p[7] << 56 |
	  (uint64_t)p[6] << 48 |
	  (uint64_t)p[5] << 40 |
	  (uint64_t)p[4] << 32 |
	  (uint64_t)p[3] << 24 |
	  (uint64_t)p[2] << 16 |
	  (uint64_t)p[1] << 8  |
	  (uint64_t)p[0]);
}

uint32_t endian_get32(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint32_t)p[0] << 24 |
	    (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8  |
	    (uint32_t)p[3]);

  return ((uint32_t)p[3] << 24 |
	  (uint32_t)p[2] << 16 |
	  (uint32_t)p[1] << 8  |
	  (uint32_t)p[0]);
}

uint16_t endian_get16(byte_t *p, enum BINFMT_ENDIAN endian) {
  if(endian == BINFMT_ENDIAN_BIG)
    return ((uint16_t)p[0] << 8 |
	    (uint16_t)p[1]);
  return ((uint16_t)p[1] << 8 |
	  (uint16_t)p[0]);
}

