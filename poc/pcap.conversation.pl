#!/usr/bin/perl 
use strict;
use warnings;

$| = 1;

#
#  Define required modules
#
use PCAP::Conversation;
#use PCAP::Xlsx::Reporter;
use Data::Dumper;

# Snarf in the file off arglist (not parameteized, should be fixed in later revision)
my $file = $ARGV[0];

printf("Extrating Conversations from:%s\n",$file);
my $C = new Pcap::Conversation;
$C->process_file($file);
printf("Extraction Completed\n");

# +
# +  // END
# +
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

