#!/usr/bin/perl 
use strict;
use warnings;

$| = 1;

#
#  Define required modules
#
use PCAP::Analysis;
use PCAP::Xlsx::Analysis;
use Data::Dumper;

# Snarf in the file off arglist (not parameteized, should be fixed in later revision)
my $file = $ARGV[0];

printf("Analysing %s\n",$file);
my $REP = new Pcap::Analysis;
$REP->process_file($file);
printf("Analysis Completed\n");

printf("Writing Report\n");
my $XLSX = new Pcap::Xlsx::Analysis($file);
$XLSX->write_report($REP->get_report()); # write report, submit base filename
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

