#include "ropc.h"

/* Search the first instruction which finish a gadget, and return the offset */
static off_t gfind_end(MEM *mem, off_t off) {
  DISASM dis;
  int len;
  len_t i;

  /* Itere the entire memory */
  for(i = off; i < mem->length; i++) {
    len = dis_instr(&dis, mem->start+i, mem->length-i, 0);

    /* Check if it's a valid instruction and a ret/call/jmp */
    if(len != UNKNOWN_OPCODE && len !=  OUT_OF_BLOCK) {
      if(dis_is_ret(&dis) || dis_is_call(&dis) || dis_is_jmp(&dis))
	return i;      
    }
  }

  return (uint32_t)-1;
}

/* Get the gadget which start at <start> and finish at <end> */
static GADGET gfind_extract_gadget(MEM *mem, off_t start, off_t end) {
  char buffer[GADGET_COMMENT_LEN];
  DISASM dis;
  GADGET g;
  int len;
  off_t i;
  int depth;

  /* Some inits */
  memset(&g, 0, sizeof(g));
  memset(buffer, 0, sizeof(buffer));
  depth = len = 0;
  
  for(i = start; i <= end; i += len) {
    len = dis_instr(&dis, mem->start + i, mem->length - i, 0);

    /* Return false if is an invalid instruction */
    if(len == UNKNOWN_OPCODE || len == OUT_OF_BLOCK)
      return g;

    /* Filter gadget if option is set */
    if(options_filter && !gfilter_gadget(dis.CompleteInstr))
      return g;

    /* Concatene the instruction to the current gadget string (check overflow) */
    if(strlen(buffer) + strlen(dis.CompleteInstr) < sizeof(buffer) - 4) {
      strcat(buffer, dis.CompleteInstr);
      strcat(buffer, " ; ");
    }
    depth++;
  }

  /* Check if the last instruction is ret
     If it's a call or jmp, add to GLIST
     only if the gadget contain one instruction
     (the call or jmp) */
  if(dis_is_ret(&dis) 
     || ((dis_is_call(&dis) || dis_is_jmp(&dis))
	 && depth == 1)) {
    g.value = mem->addr + start;
    strcpy(g.comment, buffer);
  }

  return g;
}

/* Find gadgets in memory */
static void gfind_in_mem(GLIST *glist, MEM *mem) {
  off_t end;
  off_t i;
  off_t start;
  GADGET g;

  end = 0;

  /* First, find the end of the next gadget */
  while((end = gfind_end(mem, end)) != (off_t)-1) {

    /* Some checks :) */
    if(end < options_depth)
      start = 0;
    else
      start = end - options_depth;

    /* Extract gadgets between [start ; end] */
    for(i = start; i <= end; i++) {
      if(is_good_addr(mem->addr + i, &options_bad)) {
	g = gfind_extract_gadget(mem, i, end);
	/* If we found a gadget and if gadget don't exist */
	if(g.value && glist_find(glist, g.comment) == NULL) {
	  glist_add(glist, &g);
	}           
      }
    }  
    end++;
  }
}

/* search gadget in ELF file */
void gfind_in_bin(GLIST *glist, BINFMT *bin) {
  MEM *m;

  for(m = bin->mlist->head; m != NULL; m = m->next) {
    if(m->flags & MEM_FLAG_PROT_X)
      gfind_in_mem(glist, m);
  }
}

