#!@PERL_COMMAND@
##
## Substitute for @TAG@ in STDIN stream and output to STDOUT
## Copyright (c) 2000-2011 SATOH Fumiyasu, All rights reserved.
##
## License: GNU General Public License version 2
## Date: 2011-06-22, since 2000-10-27
##

use strict;
use warnings;
use English;
use IO::File;

my $tag1 = qr/\@([A-Za-z]+(?:_[0-9A-Za-z]+)*)\@/;
my $tag2 = qr/\$[{(]([A-Za-z]+(?:_[0-9A-Za-z]+)*)[)}]/;
my $fh_in = *STDIN;
my $fh_out = *STDOUT;

if (defined($ARGV[0]) && $ARGV[0] !~ /=/) {
  my $file = shift(@ARGV);
  if ($fh_in = IO::File->new($file, 'r')) {
    die "Cannot open file: $file: $OS_ERROR";
  }
}
if (defined($ARGV[0]) && $ARGV[0] !~ /=/) {
  my $file = shift(@ARGV);
  if ($fh_out = IO::File->new($file, 'w')) {
    die "Cannot open file: $file: $OS_ERROR";
  }
}

my %text = ();
## Read tag names and values
while (defined(my $line = DATA->getline())) {
  if ($line =~ /^(\w+)=(["']?)(.*)(\2)$/) {
    $text{lc($1)} = $3;
  }
}
## Override tags by command-line arguments if specified
foreach my $arg (@ARGV) {
  if ($arg =~ /^(\w+)=(.*)$/) {
    $text{lc($1)} = $2;
  }
}

while (defined(my $line = $fh_in->getline())) {
  $line =~ s#$tag1#
    my $s;
    if (exists($text{lc($1)})) {
      $s = $text{lc($1)};
      while ($s =~ s/$tag2/exists($text{lc($1)}) ? $text{lc($1)} : "XXX Unknown: $1 XXX"/ge) {};
    } else {
      $s = "XXX Unknown: $1 XXX"
    }
    $s;
  #ge;
  $fh_out->print($line);
}

exit(0);

__DATA__
