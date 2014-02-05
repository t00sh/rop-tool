#include "ropc.h"

static void free_string(STRING *s) {
  free(s->data);
  free(s);
}
void free_strings(STRINGS *s) {
  uint32_t i;
  for(i = 0; i < s->entries; i++) {
    free_string(s->lst[i]);
  }
  s->entries_alloc = 0;
  s->entries = 0;
  free(s->lst);
}

void add_string(STRINGS *lst, STRING *string) {
  STRING *new, data;
  void* tmp;

  if((new = malloc(sizeof(*new))) == NULL)
    SYSCALL_FATAL_ERROR("OUT of memory");

  data = memdup(string);
  new->addr = data.addr;
  new->data = data.data;
  new->length = data.length;

  if(lst->entries_alloc <= lst->entries) {
    lst->entries_alloc += 0x5000;
    if(lst->entries_alloc <= lst->entries)
      FATAL_ERROR("Integer overflow");

    tmp = realloc(lst->lst, lst->entries_alloc*sizeof(*new));
    if(tmp == NULL)
      SYSCALL_FATAL_ERROR("OUT of memory");
    lst->lst = tmp;
  }

  lst->lst[lst->entries] = new;
  lst->entries++;
}

void print_string(STRING *s) {
  char *tmp;

  tmp = data_to_opcodes(s);
  if(Options.no_colors)
    fprintf(Options.out, "0x%.8x -> \"%s\"", s->addr, tmp);
  else
    fprintf(Options.out,
	    COLOR_BLACK COLOR_BG_WHITE "0x%.8x " 
	    COLOR_RESET " -> " 
	    COLOR_RED "\"%s\""
	    COLOR_RESET, 
	    s->addr, tmp);

  if(!s->addr) {
    fprintf(Options.out, " (NOT FOUND)");
  }
  fprintf(Options.out, "\n");
  free(tmp);
}

void print_strings(STRINGS *s) {
  uint32_t i;

  for(i = 0; i < s->entries; i++) {
    print_string(s->lst[i]);
  }
  fprintf(Options.out, "%d strings found.\n", s->entries);
}

/* search the first occurence of string in data  wich isn't a bad address.
 * return the 0x00 address if the string isn't found
 */
static uint32_t searching_string(DATA *data, STRING *string) {
  uint32_t index;

  index = memsearch(data, string, 0);

  while(index != (uint32_t)-1 
	&& !is_good_addr(data->addr + index, &Options.bad_chars)) {
    index = memsearch(data, string, index+1);
  }
  
  if(index != (uint32_t)-1) {
    return data->addr + index;
  }
  return 0x00000000;
}


/* search all parts of string in data and return the list of the strings found
 */
static STRINGS searching_strings(DATA *data, STRING *string) {
  uint32_t i, j;
  STRING tmp;
  int found;
  STRINGS s;

  memset(&s, 0, sizeof(s));

  for(i = 0; i < string->length; i++) {
    found = 0;

    for(j = string->length-i; j > 0; j--) {
      tmp.data = string->data+i;
      tmp.length = j;
      tmp.addr = searching_string(data, &tmp);

      if(tmp.addr != 0) {
	add_string(&s, &tmp);
	i += tmp.length-1;
	found = 1;
	break;
      }
    }
    if(!found) {
      tmp.data = string->data + i;
      tmp.length = 1;
      tmp.addr = 0;
      add_string(&s, &tmp);
    }
  }  
  return s;
}

/* search strings in a phdr, and return a list of strings */
static STRINGS searching_strings_in_phdr(ELF *elf, int ph_num, STRING *string) {
  DATA data;

  data.data = elf->data.data + elf->phdr[ph_num].p_offset;
  data.length = elf->phdr[ph_num].p_filesz;
  data.addr = elf->phdr[ph_num].p_vaddr;

  return searching_strings(&data, string);
}

static uint32_t searching_string_in_phdr(ELF *elf, int ph_num, STRING *string) {
  DATA data;

  data.data = elf->data.data + elf->phdr[ph_num].p_offset;
  data.length = elf->phdr[ph_num].p_filesz;
  data.addr = elf->phdr[ph_num].p_vaddr;

  return searching_string(&data, string);

}

/* search string in all phdr +R, and return a list of fragmented string */
STRINGS searching_strings_in_elf(ELF *elf, STRING *string) {
  int i;
  uint32_t j;
  STRINGS s;

  memset(&s, 0, sizeof(s));

  for(i = 0; i < elf->ehdr->e_phnum; i++) {
    if(elf->phdr[i].p_type == PT_LOAD) {
      if(elf->phdr[i].p_flags & PF_R) {
	if(s.entries == 0) {
	  s = searching_strings_in_phdr(elf, i, string);
	} else {
	  for(j = 0; j < s.entries; j++) {
	    if(s.lst[j]->addr == 0) {
	      s.lst[j]->addr = searching_string_in_phdr(elf, i, s.lst[j]);
	    }
	  }
	}
      }
    }
  }
  return s;
}
