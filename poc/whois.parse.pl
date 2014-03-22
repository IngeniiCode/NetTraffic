#!/usr/bin/perl -w

use PCAP::Whois;
#use Net::Whois::Parser;
use Data::Dumper;

my $hostname = $ARGV[0];

my $W = new Pcap::Whois;

my $info = $W->go($hostname); 

printf("INFO: %s\n",Dumper $info);

printf("REGISTAR: \n%s\n",$W->registrar);
printf("EMAILS: \n%s\n",$W->emails);
printf("NAMESERVERS: \n%s\n",$W->nameservers);


exit;

