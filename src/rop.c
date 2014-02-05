#include "ropc.h"

/* Options */
OPTIONS Options = {
  .search_gadget = 0,
  .search_string = 0,
  .filename      = "a.out",
  .call          = 0,
  .depth         = 5,
  .bad_chars     = {NULL, 0, 0},
  .filter        = 0,
  .no_colors     = 0,
  .stage0        = 0,
  .out           = NULL,
  .att_syntax     = 0
};

ELF File;
DATA String;

void version(void) {
  printf("%s version %s\n", PROGNAME, VERSION);
  printf("Compiled the %s at %s\n", __DATE__, __TIME__);
  exit(0);
}

/* @Function : usage()
 * @PARAM 1  : program name
 * @RETURN   : void
 *
 * @DESC     : Display program options
 */
void usage(const char *progname) {
  printf("Usage : %s [options]\n", progname);
  printf("Options : \n");
  printf("  -0             Genere stage0.\n");
  printf("  -a             Use AT&T syntax.\n");
  printf("  -b <bad>       Bad chars on address.\n");
  printf("  -c             With -g, stop gadgets with jmp/call.\n");
  printf("  -d <depth>     Depth for gadgets searching.\n");
  printf("  -g             Search gadgets.\n");
  printf("  -f <file>      Search on file.\n");
  printf("  -F             Filter gadgets.\n");
  printf("  -h             Print help.\n");  
  printf("  -N             No colors.\n");
  printf("  -o             Specifie an output file. (Use -N with this option)\n");
  printf("  -s <string>    Search string in memory.\n");
  printf("  -v             Print current version.\n");
  exit(0);
}

/* @Function : usage()
 * @PARAM 1  : arg number
 * @PAREM 2  : arg array
 * @RETURN   : void
 *
 * @DESC     : Parse command line options
 */
void handle_options(int argc, char **argv) {
  int opt;
  char *progname = argv[0];
  const struct option opts[] = {
    {"stage0",      no_argument,       NULL, '0'},
    {"stage1",      no_argument,       NULL, '1'},
    {"att",         no_argument,       NULL, 'a'},
    {"call",        no_argument,       NULL, 'c'},
    {"bad",         required_argument, NULL, 'b'},
    {"depth",       required_argument, NULL, 'd'},
    {"file",        required_argument, NULL, 'f'},
    {"filter",      no_argument,       NULL, 'F'},
    {"gadget",      no_argument,       NULL, 'g'},
    {"help",        no_argument,       NULL, 'h'},
    {"no-colors",   no_argument,       NULL, 'N'},
    {"output",      required_argument, NULL, 'o'},
    {"string",      required_argument, NULL, 's'},
    {"version",     no_argument,       NULL, 'v'},
    {NULL,          0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "01ab:cd:f:FghNo:s:v", opts, NULL)) != -1) {
    switch(opt) {
    case '0':
      Options.stage0 = 1;
      break;

    case 'a':
      Options.att_syntax = 1;
      break;

    case 'b':
      Options.bad_chars = opcodes_to_data(optarg);
      break;

    case 'c':
      Options.call = 1;
      break;

    case 'd':
      Options.depth = atoi(optarg);
      break;

    case 'g':
      Options.search_gadget = 1;
      break;

    case 'f':
      strncpy(Options.filename, optarg, MAX_PATH_LEN-1);
      Options.filename[MAX_PATH_LEN-1] = '\0';
      break;

    case 'F':
      Options.filter = 1;
      break;

    case 'h':
      usage(progname);
      break;

    case 'N':
      Options.no_colors = 1;
      break;

    case 'o':
      Options.out = fopen(optarg, "w");
      if(Options.out == NULL)
	SYSCALL_FATAL_ERROR("Can't open %s", optarg);
	break;

    case 's':
      String = opcodes_to_data(optarg);
      Options.search_string = 1;
      break;

    case 'v':
      version();
      break;

    default:
      usage(progname);      
    }
  }
  if(Options.search_string == 0 && Options.search_gadget == 0) {
    printf("You must specifie -g or -s option !\n");
    usage(progname);
  }

  if(Options.depth <= 0 || Options.depth > MAX_DEPTH) {
    printf("Bad value for depth !\n");
    exit(-1);
  }
}


int main(int argc, char **argv) {
  GADGETS g;
  STRINGS s;

  memset(&s, 0, sizeof(s));
  memset(&g, 0, sizeof(g));

  handle_options(argc, argv);

  if(Options.out == NULL)
    Options.out = stdout;
  
  load_elf(Options.filename, &File);


  /* Search gadgets */
  if(Options.search_gadget) {
    searching_gadgets_in_elf(&g, &File);
    print_gadgets(&g);
    free_gadgets(&g);
  }

  if(Options.stage0) {
    stage0_strcpy();
  } else if(Options.search_string) {
    s = searching_strings_in_elf(&File, &String);
    print_strings(&s);
    free_strings(&s);
  }


  if(Options.bad_chars.data)
    free(Options.bad_chars.data);
  if(String.data)
    free(String.data);

  free_elf(&File);   

  if(Options.out != stdout)
    fclose(Options.out);

  return 0;
}
