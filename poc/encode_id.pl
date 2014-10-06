#!/usr/bin/perl
 
use strict;
use warnings;

# =============================
#  Define required modules
# =============================
use URI::Escape;

# =================================
#  Define global scoped variables
# =================================
my $id;
my $file;
my $encoded;

# =================================
$| = 1;
# =================================

# =================================
#  App Info Retrieval 
# =================================

# Snarf in the file off arglist (not parameteized, should be fixed in later revision)
$id   = $ARGV[0];
$file = $ARGV[1];
printf("ID: %s\n",$file);

$encoded = uri_escape($id);

printf("FNAME:  %s.%s\n",$encoded,$file);

# +
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

