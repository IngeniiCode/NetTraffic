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

printf("Extrating Conversations from:%s\n",$file);
my $C = new Pcap::Conversation;
my $REPORT = $C->process_file($file);
printf("Extraction Completed\n");

printf("Writing report for %s\n",$file);
my $X = Pcap::Xlsx::Reporter->new($file);
my $outfile = $X->write_report($REPORT);
printf("Report written to: %s\n",$outfile);

#printf("CONVERSATIONS\n");
#foreach(my $ix=0;$ix < scalar(keys %{$REPORT->{SYN}});$ix++){
#	my $rec = $REPORT->{SYN}{$ix};
#	printf("[%06d]  %s => %s  --  %s \n",$ix,$rec->{src_ip},$rec->{dest_ip},$rec->{service}||'');
#}
# +
# +  // END
# +
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

