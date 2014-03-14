#include "ropc.h"

/*
 * %X  : hexadécimal value
 * %R  : any 32 bits register (eax, ebx, ecx, edx, esi, edi, esp, ebp)
 * %r  : any 16 bits register (ax, bx, cx, dx, si, di)
 * %b : any 8 bits register (al, bl, cl, dl)
 * %% : '%' char
 */
static const char *intel_filters[] = {
  "pop %R",
  "popa",

  "push %R",
  "pusha",

  "add %R,  [%X]",
  "add %R,  [%R+%X]",
  "add %R,  [%R-%X]",
  "add %R,  [%R]",
  "add %R, %X",
  "add %R, %R",
  "add  [%R], %R",
  "add  [%R+%X], %R",
  "add  [%R-%X], %R",

  "int %X",
  "call %R",
  "call  [%R]",
  "jmp  [%R]",
  "jmp %R",

  "mov %R, %R",
  "mov  [%R+%X], %R",
  "mov  [%R-%X], %R",
  "mov  [%R], %R",
  "mov %R,  [%R]",
  "mov %R,  [%R+%X]",
  "mov %R,  [%R-%X]",
  "mov %b, %b",

  "add  [%R], %b",
  "add  [%R+%X], %b",
  "add  [%R-%X], %b",

  "xchg %R, %R",

  "inc %R",
  "inc %r",
  "inc %b",

  "dec %R",
  "dec %r",
  "dec %b",

  "leave ",
  "ret ",
  NULL
};

static const char *att_filters[] = {
  "popl %%%R",
  "popa",

  "pushl %%%R",
  "pusha",

  "addl %%%R, (%%%R)",
  "addl %%%R, $%X",
  "addl %%%R, %%%R",
  "addl %%%R, (%%%R)",

  "intb $%X",
  "calll *(%%%R)",
  "jmpl *(%%%R)",

  "mov %%%R, %%%R",
  "movl %%%R, (%%%R)",
  "mov (%%%R), %%%R",
  "movb %%%b, %%%b",

  "xchg %%%R, %%%R",

  "incl %%%R",
  "incb %%%b",

  "decl %%%R",
  "decb %%%b",

  "leavel ",
  "ret ",
  NULL
};

static int _gfilter_gadget(char *instr, const char **filters) {
  int i;
  const char *p1;
  char *p2;

  for(i = 0; filters[i] != NULL; i++) {
    p1 = filters[i];
    p2 = instr;

    while(*p1 != '\0' && *p2 != '\0') {
      if(*p1 == '%') {

	p1++;
	if(*p1 == '%') {
	  if(*p2 != '%')
	    break;
	}
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

/* Check if instruction match filters */
int gfilter_gadget(char *instr) {
  if(options_flavor == FLAVOR_INTEL)
    return _gfilter_gadget(instr, intel_filters);
  return _gfilter_gadget(instr, att_filters);
}
