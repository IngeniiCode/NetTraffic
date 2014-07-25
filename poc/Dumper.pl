#!/usr/bin/perl
 
use strict;
use warnings;

# =============================
#  Define required modules
# =============================
use File::ParseName;
use Solr::Application;
use Image::GetLogo;
use PCAP::Conversation;
use Reporter::AppDetex;
use Data::Dumper;
use JSON qw( encode_json );  # From CPAN
use Solr::Base;

# =================================
#  Define global scoped variables
# =================================
my $SOLR = new Solr::Base();
my $AppInfo;
my $F;
my $C;
my $REP;
my $IMG;
my $outfile;
my $logoFile;
my $REPORT;
my $appID;
my $file;

# =================================
$| = 1;
# =================================

# =================================
#  App Info Retrieval 
# =================================

# Snarf in the file off arglist (not parameteized, should be fixed in later revision)
$file = $ARGV[0];

$C      = new Pcap::Conversation;
$REPORT = encode_json($C->process_file($file));

printf("STREAM: %s\n",$REPORT);
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

