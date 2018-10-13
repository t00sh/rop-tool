/************************************************************************/
/* rop-tool - A Return Oriented Programming and binary exploitation     */
/*            tool                                                      */
/*                                                                      */
/* Copyright 2013-2018, -TOSH-                                          */
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
#include "disassemble.h"
#include "binfmt.h"


/* =========================================================================
   This file implement filters and registers for ARM arch
   ======================================================================= */

const char *r_filter_arm[] = {
  "pop {%R}",
  "pop {%R, %R}",
  "pop {%R, %R, %R}",
  "pop {%R, %R, %R, %R}",
  "pop {%R, %R, %R, %R, %R}",
  "pop {%R, %R, %R, %R, %R, %R}",
  "pop {%R, %R, %R, %R, %R, %R, %R}",
  "pop {%R, %R, %R, %R, %R, %R, %R, %R}",
  "pop {%R, %R, %R, %R, %R, %R, %R, %R, %R}",
  "push {%R}",
  "push {%R, %R}",
  "push {%R, %R, %R}",
  "push {%R, %R, %R, %R}"
  "push {%R, %R, %R, %R, %R}",
  "push {%R, %R, %R, %R, %R, %R}",
  "push {%R, %R, %R, %R, %R, %R, %R}",
  "push {%R, %R, %R, %R, %R, %R, %R, %R}",
  "push {%R, %R, %R, %R, %R, %R, %R, %R, %R}",
  "str%C %R, %R, [%R]",
  "str %R, [%R]",
  "ldr %R, [%R]",
  "add %R, %R, #%X",
  "add %R, %R, %R",
  "sub %R, %R, #%X",
  "sub %R, %R, %R",
  "mov%C%C %R, %R",
  "mov %R, %R",
  NULL,
};

const char *r_filter_arm_end[] = {
  "pop {pc}",
  "pop {%R, pc}",
  "pop {%R, %R, pc}",
  "pop {%R, %R, %R, pc}",
  "pop {%R, %R, %R, %R, pc}",
  "pop {%R, %R, %R, %R, %R, pc}",
  "pop {%R, %R, %R, %R, %R, %R, pc}",
  "pop {%R, %R, %R, %R, %R, %R, %R, pc}",
  "pop {%R, %R, %R, %R, %R, %R, %R, %R, pc}",
  "blx %R",
  "bl%C%C %R",
  "bl %R",
  "bl%C%C %R",
  NULL,
};

const char *r_filter_arm_registers[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "pc", "fp", "sl", "lr",
  "sb",
  NULL
};

/****************************************************************/

const char *r_filter_arm64[] = {
  NULL,
};

const char *r_filter_arm64_end[] = {
  "ret ",
  NULL,
};

const char *r_filter_arm64_registers[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "pc", "fp", "sl", "lr",
  "sb", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
  "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
  "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
  NULL
};
