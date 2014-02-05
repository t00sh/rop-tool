#include "ropc.h"

/*
 * %X  : hexadécimal value
 * %R  : any 32 bits register (eax, ebx, ecx, edx, esi, edi, esp, ebp)
 * %r  : any 16 bits register (ax, bx, cx, dx, si, di)
 * %b : any 8 bits register (al, bl, cl, dl)
 */
static const char *Filters[] = {
  "pop %R",
  "popa",

  "push %R",
  "pusha",

  "add %R,[%X]",
  "add %R,[%R+%X]",
  "add %R,[%R-%X]",
  "add %R,[%R]",
  "add %R,%X",
  "add %R,%R",
  "add [%R],%R",
  "add [%R+%X],%R",
  "add [%R-%X],%R",

  "int %X",
  "call %R",
  "call [%R]",
  "jmp [%R]",
  "jmp %R",

  "mov %R,%R",
  "mov [%R+%X],%R",
  "mov [%R-%X],%R",
  "mov [%R],%R",
  "mov %R,[%R]",
  "mov %R,[%R+%X]",
  "mov %R,[%R-%X]",

  "add [%R],%b",
  "add [%R+%X],%b",
  "add [%R-%X],%b",

  "xchg %R,%R",

  "leave",
  "ret",
  "retn %X",
};

/* Check if instruction match filters */
int filter_gadget(char *instr) {
  uint32_t i;
  const char *p1;
  char *p2;


  for(i = 0; i < sizeof(Filters)/sizeof(*Filters); i++) {
    p1 = Filters[i];
    p2 = instr;

    while(*p1 != '\0' && *p2 != '\0') {
      if(*p1 == '%') {

	p1++;
	if(*p1 == 'X') {
	  if(*p2 != '0')
	    break;
	  strtol(p2, &p2, 0);
	  p2--;
	}
	if(*p1 == 'R') {
	  if(strncmp("eax", p2, 3) &&
	     strncmp("ebx", p2, 3) &&
	     strncmp("ecx", p2, 3) &&
	     strncmp("edx", p2, 3) &&
	     strncmp("esp", p2, 3) &&
	     strncmp("ebp", p2, 3) &&
	     strncmp("esi", p2, 3) &&
	     strncmp("edi", p2, 3))
	    break;
	  p2 += 2;
	}
	if(*p1 == 'r') {
	  if(strncmp("ax", p2, 2) &&
	     strncmp("bx", p2, 2) &&
	     strncmp("cx", p2, 2) &&
	     strncmp("dx", p2, 2) &&
	     strncmp("di", p2, 2) &&
	     strncmp("si", p2, 2))
	    break;
	  p2++;
	}

	if(*p1 == 'b') {
	  if(strncmp("al", p2, 2) &&
	     strncmp("bl", p2, 2) &&
	     strncmp("cl", p2, 2) &&
	     strncmp("dl", p2, 2))
	    break;
	  p2++;

	}
      } else {
	if(*p1 != *p2)
	  break;
      } 
      p1++;
      p2++;
    }
    if(*p1 == '\0' && *p2 == '\0')
      return 1;
  }
  return 0;
}
