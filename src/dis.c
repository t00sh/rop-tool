#include "ropc.h"

int dis_instr(DISASM *dis, byte_t *code, len_t len, int arch) {

  memset(dis, 0, sizeof(DISASM));

  dis->Archi = arch;
  dis->SecurityBlock = len;
  dis->EIP = (UIntPtr)code;  

  if(options_flavor == FLAVOR_ATT)
    dis->Options = PrefixedNumeral + ATSyntax;
  else if(options_flavor == FLAVOR_INTEL)
    dis->Options = PrefixedNumeral + NasmSyntax;

  return Disasm(dis);
}

int dis_is_call(DISASM *dis) {
  return (dis->Instruction.BranchType == CallType);
}

int dis_is_jmp(DISASM *dis) {
  return (dis->Instruction.BranchType == JmpType);
}

int dis_is_ret(DISASM *dis) {
  return (dis->Instruction.BranchType == RetType);
}
