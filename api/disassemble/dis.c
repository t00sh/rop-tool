#include "api/disassemble.h"

/* Init the disassembler */
int r_disa_init(r_disa_s *dis, r_binfmt_arch_e arch) {
  int cs_mode;

  assert(dis != NULL);

  memset(dis, 0, sizeof(*dis));

  if(arch == R_BINFMT_ARCH_X86_64)
    cs_mode = CS_MODE_64;
  else if(arch == R_BINFMT_ARCH_X86)
    cs_mode = CS_MODE_32;
  else
    return 0;

  if(cs_open(CS_ARCH_X86, cs_mode, &dis->handle) != CS_ERR_OK)
    return 0;

  dis->arch = arch;
  dis->flavor = R_DISA_FLAVOR_INTEL;

  return 1;
}

int r_disa_set_flavor(r_disa_s *dis, r_disa_flavor_e flavor) {

  assert(dis != NULL);

  dis->flavor = flavor;

  if(flavor == R_DISA_FLAVOR_INTEL)
    return cs_option(dis->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL) == CS_ERR_OK;
  if(flavor == R_DISA_FLAVOR_ATT)
    return cs_option(dis->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) == CS_ERR_OK;

  return 0;
}

/* Free the instruction list */
void r_disa_free_instr_lst(r_disa_s *dis) {

  assert(dis != NULL);

  if(dis->instr_lst.count > 0) {
    cs_free(dis->instr_lst.head, dis->instr_lst.count);
    dis->instr_lst.count = 0;
    dis->instr_lst.head = NULL;
    dis->instr_lst.cur = 0;
  }
}

/* Close the disassembler */
void r_disa_close(r_disa_s *dis) {
  assert(dis != NULL);

  cs_close(&dis->handle);
  r_disa_free_instr_lst(dis);
}

/* Disassemble code */
size_t r_disa_code(r_disa_s *dis, byte_t *code, len_t len, addr_t addr, size_t count) {

  assert(dis != NULL);
  assert(code != NULL);

  r_disa_free_instr_lst(dis);
  dis->instr_lst.count = cs_disasm(dis->handle, code, len, addr, count, &dis->instr_lst.head);

  return dis->instr_lst.count;
}

r_disa_instr_t* r_disa_next_instr(r_disa_s *dis) {
  r_disa_instr_t *instr;

  assert(dis != NULL);

  if(dis->instr_lst.cur >= dis->instr_lst.count)
    return NULL;

  instr = &dis->instr_lst.head[dis->instr_lst.cur];
  dis->instr_lst.cur++;

  return instr;
}

/* Check if last instruction is a CALL */
int r_disa_end_is_call(r_disa_s *dis) {
  size_t end;

  assert(dis != NULL);

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.head[end].mnemonic, "call", 4));
}

/* Check if last instruction is a JMP */
int r_disa_end_is_jmp(r_disa_s *dis) {
  size_t end;

  assert(dis != NULL);

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.head[end].mnemonic, "jmp", 3));
}

/* Check if last instruction is a RET */
int r_disa_end_is_ret(r_disa_s *dis) {
  size_t end;

  assert(dis != NULL);

  if(dis->instr_lst.count == 0)
    return 0;

  end = dis->instr_lst.count-1;
  return (!strncmp(dis->instr_lst.head[end].mnemonic, "ret", 3));
}

/* Transform the instr list to string : [INSTR1; [INSTR2];...]
   The string is allocated with malloc, she must be freed by the caller
*/
char* r_disa_instr_lst_to_str(r_disa_s *dis) {
  char *string;
  size_t i;
  size_t size;

  assert(dis != NULL);

  size = 0;

  for(i = 0; i < dis->instr_lst.count; i++) {
    size += strlen(dis->instr_lst.head[i].mnemonic);
    size += strlen(dis->instr_lst.head[i].op_str);
    size += 3;
  }

  size++;

  string = r_utils_malloc(size);
  *string = '\0';

  for(i = 0; i < dis->instr_lst.count; i++) {
    strcat(string, dis->instr_lst.head[i].mnemonic);
    strcat(string, " ");
    strcat(string, dis->instr_lst.head[i].op_str);
    strcat(string, "; ");
  }

  return string;
}

/* Get the flavor corresponding to a string */
r_disa_flavor_e r_disa_string_to_flavor(const char *string) {
  if(!strcmp(string, "intel"))
    return R_DISA_FLAVOR_INTEL;
  if(!strcmp(string, "att"))
    return R_DISA_FLAVOR_ATT;

  return R_DISA_FLAVOR_UNDEF;
}
