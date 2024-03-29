#!/usr/bin/perl
 
use strict;
use warnings;

# =============================
#  Define required modules
# =============================
use File::ParseName;
use Image::GetLogo;
use PCAP::Conversation;
use Reporter::Interrogator;
use Data::Dumper;
use Solr::Base;

# =================================
#  Define global scoped variables
# =================================
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
printf("Intake File: %s\n",$file);

# =================================
#  Report Prep
# =================================
my $tcfg = {
	orig_file => $file,
};
$REP  = Reporter::Interrogator->new($tcfg);

printf("Extrating Conversations from:%s\n",$file);
$C      = new Pcap::Conversation;
$REPORT = $C->process_file($file);
printf("Extraction Completed\n");

printf("Writing report for %s\n",$file);
$outfile = $REP->write_report($REPORT);

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

