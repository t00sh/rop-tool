#include "ropc.h"

/* Options */
char options_filename[PATH_MAX]       = "./a.out";
enum MODE options_mode                = MODE_GADGET;
enum FLAVOR options_flavor            = FLAVOR_INTEL;
enum OUTPUT options_output            = OUTPUT_PERL;
int options_color                     = 1;
uint8_t options_depth                 = 10;
int options_filter                    = 1;
BLIST options_bad                     = {NULL, 0};
BLIST options_search                  = {NULL, 0};

/* Display program version & quit */
static void version(void) {
  printf("%s version %s\n", PACKAGE, VERSION);
  printf("Compiled the %s at %s\n", __DATE__, __TIME__);
  exit(EXIT_SUCCESS);
}

/* Display program usage & quit */
static void usage(const char *progname) {
  printf("Usage : %s [options]\n", progname);
  printf("Tool for searching Gadgets in ELF binaries\n");
  printf("\n");
  printf("MODES\n");
  printf("  -G --gadget        Gadget searching mode\n");
  printf("  -S --string        String searching mode\n");
  printf("  -P --payload       Payload generator mode\n");
  printf("\n");
  printf("Gadget Mode\n");
  printf("  -b, --bad          Specify bad chars\n");
  printf("  -d, --depth        Specify the depth searching\n");
  printf("  -f, --file         Specify the file\n");
  printf("  -a, --all          Display all gadgets\n");
  printf("  -n, --no-color     No colored output\n");
  printf("  -F, --flavor       Specify the flavor (intel or att)\n");
  printf("\n");
  printf("String Mode\n");
  printf("  -b, --bad          Specify bad chars\n");
  printf("  -f, --file         Specify the file\n");
  printf("  -s, --search       Specify the string to search\n");
  printf("  -n, --no-color     No colored output\n");
  printf("\n");
  printf("General options\n");
  printf("  -h, --help         Print help\n");
  printf("  -v, --version      Print version\n");
  exit(EXIT_SUCCESS);
}

enum FLAVOR options_set_flavor(const char *flavor) {
  if(!strcmp(flavor, "intel"))
    return FLAVOR_INTEL;
  if(!strcmp(flavor, "att"))
    return FLAVOR_ATT;

  FATAL_ERROR("%s: bad flavor", flavor);

  return FLAVOR_NONE;
}

void options_parse(int argc, char **argv) {
  int opt;
  char *progname = argv[0];
  const struct option opts[] = {
    {"flavor",      required_argument, NULL, 'F'},
    {"string",      no_argument,       NULL, 'S'},
    {"search",      required_argument, NULL, 's'},
    {"bad",         required_argument, NULL, 'b'},
    {"depth",       required_argument, NULL, 'd'},
    {"file",        required_argument, NULL, 'f'},
    {"all",         no_argument,       NULL, 'a'},
    {"gadget",      no_argument,       NULL, 'G'},
    {"help",        no_argument,       NULL, 'h'},
    {"no-color",    no_argument,       NULL, 'n'},
    {"version",     no_argument,       NULL, 'v'},
    {NULL,          0,                 NULL, 0  }
  };

  while((opt = getopt_long(argc, argv, "F:Ss:b:d:f:aGhnv", opts, NULL)) != -1) {
    switch(opt) {
    case 'F':
      options_flavor = options_set_flavor(optarg);
      break;

    case 'S':
      options_mode = MODE_STRING;
      break;

    case 's':
      options_search = opcodes_to_blist(optarg);
      break;

    case 'b':
      options_bad = opcodes_to_blist(optarg);
      break;

    case 'd':
      options_depth = atoi(optarg);
      break;

    case 'G':
      options_mode = MODE_GADGET;
      break;

    case 'f':
      strncpy(options_filename, optarg, PATH_MAX-1);
      options_filename[PATH_MAX-1] = '\0';
      break;

    case 'a':
      options_filter = 0;
      break;

    case 'h':
      usage(progname);
      break;

    case 'n':
      options_color = 0;
      break;

    case 'v':
      version();
      break;

    default:
      usage(progname);      
    }
  }

  if(options_depth > MAX_DEPTH)
    FATAL_ERROR("Depth must be in range 0-%d", MAX_DEPTH);
}
