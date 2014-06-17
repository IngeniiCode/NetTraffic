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
printf("Intake File: %s\n",$file);

# Parse out the appID from filename, if possible.  This should be in a URL encoded format
# to protect nasties like slashes etc. etc. etc.
$F     = new File::ParseName($file);
$appID = $F->get_app_id();
printf("AppID: %s\n",$appID);

# Set image processing paths
$IMG = new Image::GetLogo($F->path());

# once parsed from filename, then need to grab some of the parts from Solr for creating the 
# summary page.
$AppInfo = $SOLR->getApp($appID);

printf("Filename:     %s\n",$file);
printf("AppInfo: %s\n",Dumper $AppInfo);

# Grab the image
$logoFile = $IMG->getImage($AppInfo->{logo});
printf("LogoFile:     %s\n",$logoFile);

# =================================
#  Report Prep
# =================================
my $tcfg = {
	orig_file => $file,
	title     => $AppInfo->{title},
	desc      => $AppInfo->{description},
	publisher => $AppInfo->{publisher},
	store     => $AppInfo->{store},
	price     => $AppInfo->{price},
	category  => $AppInfo->{category},
	downloads => $AppInfo->{numDownload},
	logo      => $logoFile,
};
$REP  = Reporter::Interrogator::AppDetex->new($tcfg);

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

