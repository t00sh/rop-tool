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

#ifndef DEF_API_UTILS_PRINT_H
#define DEF_API_UTILS_PRINT_H

/* =========================================================================
   R_UTILS_COLOR_RESET    : a constant used to recover color state
   R_UTILS_FG_COLOR_*     : foreground colors
   R_UTILS_BG_COLOR_*     : background colors
   R_UTILS_PRINT_COLORED  : a macro used to print colored (or not) strings
   R_UTILS_FPRINT_COLORED : a macro used to print colored (or not) strings
                            throw a stream
   ======================================================================= */

#define R_UTILS_COLOR_RESET    "\033[m"

#define R_UTILS_FG_COLOR_BLACK    "\033[30m"
#define R_UTILS_FG_COLOR_RED      "\033[31m"
#define R_UTILS_FG_COLOR_GREEN    "\033[32m"
#define R_UTILS_FG_COLOR_YELLOW   "\033[33m"
#define R_UTILS_FG_COLOR_BLUE     "\033[34m"
#define R_UTILS_FG_COLOR_MAGENTA  "\033[35m"
#define R_UTILS_FG_COLOR_CYAN     "\033[36m"
#define R_UTILS_FG_COLOR_WHITE    "\033[37m"

#define R_UTILS_BG_COLOR_BLACK    "\033[40m"
#define R_UTILS_BG_COLOR_RED      "\033[41m"
#define R_UTILS_BG_COLOR_GREEN    "\033[42m"
#define R_UTILS_BG_COLOR_YELLOW   "\033[43m"
#define R_UTILS_BG_COLOR_BLUE     "\033[44m"
#define R_UTILS_BG_COLOR_MAGENTA  "\033[45m"
#define R_UTILS_BG_COLOR_CYAN     "\033[46m"
#define R_UTILS_BG_COLOR_WHITE    "\033[47m"

#define R_UTILS_FPRINT_COLORED(stream,color,c_str,...) do { \
    if(color) {                                             \
      fprintf(stream, c_str);                               \
      fprintf(stream, __VA_ARGS__);                         \
      fprintf(stream, R_UTILS_COLOR_RESET);                 \
    } else {                                                \
      fprintf(stream,__VA_ARGS__);                          \
    }                                                       \
  }while(0);

#define R_UTILS_PRINT_COLORED(color,c_str,...) do {             \
    R_UTILS_FPRINT_COLORED(stdout, color, c_str, __VA_ARGS__);  \
  } while(0)



#define R_UTILS_PRINT_WHITE_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c,    \
                                                                  R_UTILS_FG_COLOR_WHITE R_UTILS_BG_COLOR_BLACK, \
                                                                  __VA_ARGS__)
#define R_UTILS_PRINT_BLACK_BG_WHITE(c,...) R_UTILS_PRINT_COLORED(c,    \
                                                                  R_UTILS_FG_COLOR_BLACK R_UTILS_BG_COLOR_WHITE, \
                                                                  __VA_ARGS__)
#define R_UTILS_PRINT_RED_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c,      \
                                                                R_UTILS_FG_COLOR_RED R_UTILS_BG_COLOR_BLACK, \
                                                                __VA_ARGS__)
#define R_UTILS_PRINT_GREEN_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c,    \
                                                                  R_UTILS_FG_COLOR_GREEN R_UTILS_BG_COLOR_BLACK, \
                                                                  __VA_ARGS__)
#define R_UTILS_PRINT_YELLOW_BG_BLACK(c,...) R_UTILS_PRINT_COLORED(c,   \
                                                                   R_UTILS_FG_COLOR_YELLOW R_UTILS_BG_COLOR_BLACK, \
                                                                   __VA_ARGS__)
#define R_UTILS_PRINT_BLUE_BG_WHITE(c,...) R_UTILS_PRINT_COLORED(c,     \
                                                                 R_UTILS_FG_COLOR_BLUE R_UTILS_BG_COLOR_WHITE, \
                                                                 __VA_ARGS__)

#define R_UTILS_FPRINT_WHITE_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s, \
                                                                      c, \
                                                                      R_UTILS_FG_COLOR_WHITE R_UTILS_BG_COLOR_BLACK, \
                                                                      __VA_ARGS__)
#define R_UTILS_FPRINT_BLACK_BG_WHITE(s,c,...) R_UTILS_FPRINT_COLORED(s, \
                                                                      c, \
                                                                      R_UTILS_FG_COLOR_BLACK R_UTILS_BG_COLOR_WHITE, \
                                                                      __VA_ARGS__)
#define R_UTILS_FPRINT_RED_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s,  \
                                                                    c,  \
                                                                    R_UTILS_FG_COLOR_RED R_UTILS_BG_COLOR_BLACK, \
                                                                    __VA_ARGS__)
#define R_UTILS_FPRINT_GREEN_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s, \
                                                                      c, \
                                                                      R_UTILS_FG_COLOR_GREEN R_UTILS_BG_COLOR_BLACK, \
                                                                      __VA_ARGS__)
#define R_UTILS_FPRINT_YELLOW_BG_BLACK(s,c,...) R_UTILS_FPRINT_COLORED(s, \
                                                                       c, \
                                                                       R_UTILS_FG_COLOR_YELLOW R_UTILS_BG_COLOR_BLACK, \
                                                                       __VA_ARGS__)
#define R_UTILS_FPRINT_BLUE_BG_WHITE(s,c,...) R_UTILS_FPRINT_COLORED(s, \
                                                                     c, \
                                                                     R_UTILS_FG_COLOR_BLUE R_UTILS_BG_COLOR_WHITE, \
                                                                     __VA_ARGS__)


/* =========================================================================
   WARN display an error message,
   WARNX display an error message, and the error associed to errno
   ERR display an error message & exit
   ERRX display an error message, the error associed to errno & exit
   ======================================================================= */

#define R_UTILS_WARNX(...) do {                   \
    fprintf(stderr, "[-] ");                      \
    fprintf(stderr, __VA_ARGS__);                 \
    fprintf(stderr, " : %s\n", strerror(errno));  \
  }while(0)

#define R_UTILS_WARN(...) do {                  \
    fprintf(stderr, "[-] ");                    \
    fprintf(stderr, __VA_ARGS__);               \
    fprintf(stderr, "\n");                      \
  }while(0)

#define R_UTILS_ERRX(...) do {                  \
    R_UTILS_WARNX(__VA_ARGS__);                 \
    exit(EXIT_FAILURE);                         \
  }while(0)


#define R_UTILS_ERR(...) do {                   \
    R_UTILS_WARN(__VA_ARGS__);                  \
    exit(EXIT_FAILURE);                         \
  }while(0)

#ifndef NDEBUG
#define R_UTILS_DEBUG(...) do {                 \
    fprintf(stderr, "[DEBUG] ");                \
    fprintf(stderr, __VA_ARGS__);               \
    fprintf(stderr, "\n");                      \
  }while(0)
#else
#define DEBUG(...)
#endif


#endif
