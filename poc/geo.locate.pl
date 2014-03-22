#!/usr/bin/perl -w

use PCAP::GeoLocate;
use Data::Dumper;

my $ip = $ARGV[0];

$GEO = new Pcap::GeoLocate;
$GEO->go($ip);

#printf("%s\n",$GEO->get_content_raw());
printf("DATA %s\n",Dumper $GEO->get_data());

exit;

