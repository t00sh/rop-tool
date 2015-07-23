#!/usr/bin/perl

use strict;
use warnings;


my $HEADER =
    '/************************************************************************/' . "\n" .
    '/* rop-tool - A Return Oriented Programming and binary exploitation     */' . "\n" .
    '/*            tool                                                      */' . "\n" .
    '/*                                                                      */' . "\n" .
    '/* Copyright 2013-2015, -TOSH-                                          */' . "\n" .
    '/* File coded by -TOSH-                                                 */' . "\n" .
    '/*                                                                      */' . "\n" .
    '/* This file is part of rop-tool.                                       */' . "\n" .
    '/*                                                                      */' . "\n" .
    '/* rop-tool is free software: you can redistribute it and/or modify     */' . "\n" .
    '/* it under the terms of the GNU General Public License as published by */' . "\n" .
    '/* the Free Software Foundation, either version 3 of the License, or    */' . "\n" .
    '/* (at your option) any later version.                                  */' . "\n" .
    '/*                                                                      */' . "\n" .
    '/* rop-tool is distributed in the hope that it will be useful,          */' . "\n" .
    '/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */' . "\n" .
    '/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */' . "\n" .
    '/* GNU General Public License for more details.                         */' . "\n" .
    '/*                                                                      */' . "\n" .
    '/* You should have received a copy of the GNU General Public License    */' . "\n" .
    '/* along with rop-tool.  If not, see <http://www.gnu.org/licenses/>     */' . "\n" .
    '/************************************************************************/' . "\n";

foreach my $file(@ARGV) {
    process_file($file);
}

sub process_file {
    my $f = shift;
    my $file;
    my $line;
    my $line_num = 1;

    open (F, '<', $f) || die $@;

    while(($line = <F>)) {
        last if($line !~ m/^\/\*.+\*\//);

        if($line_num == 2 && ($line !~ m/ rop-tool /)) {
            close F;
            return;
        }

        $line_num++;
    }

    if($line_num < 20) {
        close F;
        return;
    }

    $file = $HEADER . $line;
    while(($line = <F>)) {
        $file .= $line;
    }

    close F;


    open(F, '>', $f) || die $@;

    print F $file;

    close F;

    print "[+] $f done\n";
}
