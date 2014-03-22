#!/usr/bin/perl 
use strict;
use warnings;

$| = 1;

#
#  Define required modules
#
use PCAP::Conversation;
use PCAP::Xlsx::Reporter;
use Data::Dumper;

# Snarf in the file off arglist (not parameteized, should be fixed in later revision)
my $file = $ARGV[0];

printf("Extrating Conversations %s\n",$file);
my $C = new Pcap::Conversation;
$C->process_file($file);
printf("Extraction Completed\n");

printf("Writing Conversations Report\n");
my $XLSX = new Pcap::Xlsx::Reporter($file);
$XLSX->write_report($C->get_report()); # write report, submit base filename
printf("Report generated for %s\n",$file);

# +
# +  // END
# +
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

