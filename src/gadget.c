#include "ropc.h"

/* Get the entry ID in the gadget table */
static uint32_t get_gadget_table_entry(GADGET *g) {
  uint32_t ret;
  const unsigned char *ptr;

  ptr = (unsigned char*)g->string;
  ret = 0;

  while(*ptr != '\0') {
    ret += *ptr;
    ptr++;
  }
  return ret % GADGET_TABLE_SIZE;
}

/* Return 1 if gadget already exist in table */
static int gadget_exists(GADGETS *l, GADGET *g) {
  uint32_t entry;
  GADGET *ptr;

  entry = get_gadget_table_entry(g);

  for(ptr = l->table[entry]; ptr != NULL; ptr = ptr->next) {
    if(!strcmp(g->string, ptr->string))
      return 1;
  }
  return 0;
}

/* free a gadget */
static void free_gadget(GADGET *g) {

  free(g->string);
  free(g);
}

/* Free gadget list */
void free_gadgets(GADGETS *g) {
  uint32_t i;
  GADGET *p, *tmp;

  for(i = 0; i < GADGET_TABLE_SIZE; i++) {
    p = g->table[i];
    while(p != NULL) {
      tmp = p->next;
      free_gadget(p);
      p = tmp;
    }
  }
}

/* Add a gadget to the GADGETS list */
static void add_gadget(GADGETS *g, GADGET *gadget) {
  uint32_t entry;
  GADGET *new;


  if((new = malloc(sizeof(*new))) == NULL)
    FATAL_ERROR("OUT of memory");
  
  entry = get_gadget_table_entry(gadget);
  
  new->string = gadget->string;
  new->addr = gadget->addr;
  new->next = g->table[entry];
  
  g->table[entry] = new;      
}

/* print a gadget */
static void print_gadget(GADGET *g) {
  if(Options.no_colors)
    fprintf(Options.out, "0x%.8x -> %s\n", g->addr, g->string);
  else 
    fprintf(Options.out, COLOR_BLACK COLOR_BG_WHITE "0x%.8x " 
	   COLOR_RESET " -> " 
	   COLOR_RED "%s\n"
	   COLOR_RESET, 
	   g->addr, g->string);
}

/* print a gadget list */
void print_gadgets(GADGETS *g) {
  GADGET *gad;
  uint32_t i;
  uint32_t found;

  found = 0;

  for(i = 0; i < GADGET_TABLE_SIZE; i++) {
    for(gad = g->table[i]; gad != NULL; gad = gad->next) {
      print_gadget(gad);
      found++;
    }
  }

  fprintf(Options.out, "%u unic gadgets found.\n", found);
}

/* search the first gadget in data */
static GADGET searching_gadget_in_data(DATA *data) {
  char intel[64];
  char att[64];
  char buffer[1024];
  INSTRUCTION inst;
  GADGET g;
  uint32_t i;
  char *ptr;
  int depth;

  depth = 0;
  i = 0;
  g.string = NULL;
  buffer[0] = '\0';

  while(i < data->length && depth < Options.depth) {
    get_instruction(&inst, data->data + i, MODE_32);
    
    if(inst.length == 0)
      break;      

    if(Options.att_syntax) {
      get_instruction_string(&inst, FORMAT_ATT, 0, att, sizeof(att));
      ptr = att;
    } else {
      ptr = intel;
    }

    get_instruction_string(&inst, FORMAT_INTEL, 0, intel, sizeof(intel));

    if(Options.filter) {
      if(!filter_gadget(intel))
	break;
    }

    if(strlen(buffer) + strlen(ptr) < sizeof(buffer) - 4) {
      strcat(buffer, ptr);
      strcat(buffer, " ; ");
    }

    if((Options.call && (inst.type == INSTRUCTION_TYPE_CALL || inst.type == INSTRUCTION_TYPE_JMP)) || inst.type == INSTRUCTION_TYPE_RET) {
      g.string = strdup(buffer);
      g.addr = data->addr;
      break;
    }
    i += inst.length;
    depth++;
  }
  
  return g;
}

/* Search gadgets in specified Segment */
static void searching_gadgets_in_phdr(GADGETS *g, ELF *elf, int phnum) {
  DATA data, tmp;
  GADGET gadget;
  uint32_t i;

  data.data = elf->data.data + elf->phdr[phnum].p_offset;
  data.length = elf->phdr[phnum].p_filesz;
  data.addr = elf->phdr[phnum].p_vaddr;

  for(i = 0; i < data.length; i++) {
    tmp.data = data.data + i;
    tmp.addr = data.addr + i;
    tmp.length = data.addr - i;

    gadget = searching_gadget_in_data(&tmp);
    if(gadget.string != NULL) {
      if(!gadget_exists(g, &gadget))
	add_gadget(g, &gadget);
      else
	free(gadget.string);
    }
  }
}
 
/* search gadget in ELF file */
void searching_gadgets_in_elf(GADGETS *g, ELF *elf) {
  int i;

  for(i = 0; i < elf->ehdr->e_phnum; i++) {
    if(elf->phdr[i].p_type == PT_LOAD) {
      if(elf->phdr[i].p_flags & PF_X) {
	searching_gadgets_in_phdr(g, elf, i);
      }
    }
  }
}

