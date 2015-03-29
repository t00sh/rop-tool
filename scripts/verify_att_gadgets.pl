#!/usr/bin/perl

use strict;
use warnings;

my %intel;
my %att;
my %att_all;

my $prog = shift || usage();
my $target = shift || usage();

open INTEL, "./$prog g $target -n -f intel |" || die "can't open $prog : $!\n";

while(my $l = <INTEL>) {
    if($l =~ m/\s(.+) -> (.+)/) {
	$intel{$1} = $2;
    }
}

close INTEL;

open ATT, "./$prog g $target -n -f att |" || die "can't open $prog : $!\n";

while(my $l = <ATT>) {
    if($l =~ m/\s(.+) -> (.+)/) {
	$att{$1} = $2;
    }
}

close ATT;

open ATT, "./$prog g $target -n -f att -a |" || die "can't open $prog : $!\n";

while(my $l = <ATT>) {
    if($l =~ m/\s(.+) -> (.+)/) {
	$att_all{$1} = $2;
    }
}

close ATT;


my $count = 0;
foreach my $k(keys %intel) {
    if(!exists($att{$k})) {
	print "[-] $att_all{$k}\n";
	$count++;
    }
}

print "$count gadgets which don't match\n";

sub usage {
    die "$0 <prog> <target>\n";
}
