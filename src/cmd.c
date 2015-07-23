/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/*                                                                      */
/* Copyright 2013-2015, -TOSH-                                          */
/* File coded by -TOSH-                                                 */
/*                                                                      */
/* This file is part of rop-tool.                                       */
/*                                                                      */
/* rop-tool is free software: you can redistribute it and/or modify     */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.                                  */
/*                                                                      */
/* rop-tool is distributed in the hope that it will be useful,          */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.                         */
/*                                                                      */
/* You should have received a copy of the GNU General Public License    */
/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */
/************************************************************************/

#include "rop.h"

static void version_cmd(int argc, char **argv);
static void help_cmd(int argc, char **argv);

void search_cmd(int argc, char **argv);
void gadget_cmd(int argc, char **argv);
void patch_cmd(int argc, char **argv);
void info_cmd(int argc, char **argv);
void dis_cmd(int argc, char **argv);

#ifndef __WINDOWS__
void heap_cmd(int argc, char **argv);
#endif

void search_help(void);
void gadget_help(void);
void patch_help(void);
void info_help(void);
void dis_help(void);

#ifndef __WINDOWS__
void heap_help(void);
#endif

typedef struct command {

  const char *name;
  const char *short_help;
  void (*help)(void);
  void (*cmd)(int,char**);

}command_s;

command_s command_list[] = {
  {"gadget",      "Search gadgets",          gadget_help,      gadget_cmd},
  {"patch",       "Patch the binary",        patch_help,       patch_cmd},
  {"info",        "Print info about binary", info_help,        info_cmd},
#ifndef __WINDOWS__
  {"heap",        "Display heap structure",  heap_help,        heap_cmd},
#endif
  {"disassemble", "Disassemble the binary",  dis_help, dis_cmd},
  //  {"payload",     "Genere payloads",         payload_help,     payload_cmd},
  {"search",      "Search on binary",        search_help,      search_cmd},
  {"help",        "Print help",              NULL,             help_cmd},
  {"version",     "Print version",           NULL,             version_cmd},
  {NULL, NULL, NULL, NULL}
};

/*
   Search a command by it's name
   If none commands match, it return -1
   If multiple commands match, it return -2
   Otherwise, it return the command index in
   command_list table
*/
static int command_search(const char *cmd) {
  int i;
  int matchs;
  int len;
  int ret;

  ret = matchs = 0;
  len = strlen(cmd);

  for(i = 0; command_list[i].name; i++) {
    if(!strncmp(command_list[i].name, cmd, len)) {
      matchs++;
      ret = i;
    }
  }

  if(matchs == 0) {
    ret = -1;
  } else if(matchs > 1) {
    ret = -2;
  }

  return ret;
}

void command_print_matchs(const char *cmd) {
   int i;
  int matchs;
  int len;

  matchs = 0;
  len = strlen(cmd);

  for(i = 0; command_list[i].name; i++) {
    if(!strncmp(command_list[i].name, cmd, len)) {

      if(matchs > 0) {
	printf(", ");
      }
      printf("%s", command_list[i].name);
      matchs++;
    }
  }
}

void command_execute(const char *cmd, int argc, char **argv) {
  int cmd_id;

  assert(cmd != NULL && argv != NULL);
  assert(argc > 0);

  if((cmd_id = command_search(cmd)) == -1) {
    R_UTILS_ERR("%s isn't a valid command, see the help.", cmd);
  } else if(cmd_id == -2) {
    printf("Too much commands match \"%s\"\n", cmd);
    printf("Did you mean : ");
    command_print_matchs(cmd);
    printf(" ?!\n");
    exit(EXIT_FAILURE);
  }

  command_list[cmd_id].cmd(argc, argv);
}

static void command_help(int cmd_id) {

  if(command_list[cmd_id].help != NULL) {
    command_list[cmd_id].help();
  } else {
    R_UTILS_ERR("No help available for command %s.", command_list[cmd_id].name);
  }

  exit(EXIT_FAILURE);
}

static void help_cmd_info(const char *cmd) {
  int cmd_id;

  if((cmd_id = command_search(cmd)) == -1) {
    R_UTILS_ERR("%s isn't a valid command, see the help.", cmd);
  } else if(cmd_id == -2) {
    R_UTILS_ERR("Too much commands match %s, be more precise.", cmd);
  }

  command_help(cmd_id);
  exit(EXIT_FAILURE);
}

void help_usage(void) {
  int i;

  printf("%s v%s\n", PACKAGE, VERSION);
  printf("Help you make binary exploits.\n\n");
  printf("Usage: %s <cmd> [OPTIONS]\n", PACKAGE);
  printf("\nCommands :\n");

  for(i = 0; command_list[i].name; i++) {
    printf("   %-15s  %s\n", command_list[i].name, command_list[i].short_help);
  }

  printf("\nTry \"%s help <cmd>\" for more informations about a command.\n", PACKAGE);
  exit(EXIT_FAILURE);
}

static void help_cmd(int argc, char **argv) {
  if(argc > 2) {
    printf("Too much arguments !\n");
    printf("   Usage : %s help\n", PACKAGE);
    printf("   Usage : %s help <cmd>\n", PACKAGE);
  } else if(argc == 2) {
    help_cmd_info(argv[1]);
  } else {
    help_usage();
  }

  exit(EXIT_FAILURE);
}

static void version_cmd(int argc, char **argv) {
  (void)argc;
  (void)argv;

  printf("%s version %s\n", PACKAGE, VERSION);
  printf("Compiled the %s at %s\n", __DATE__, __TIME__);
  exit(EXIT_FAILURE);
}
