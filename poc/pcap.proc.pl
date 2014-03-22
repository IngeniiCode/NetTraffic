#!/usr/bin/perl -w

use Net::TcpDumpLog;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Data::Dumper;
use strict;

my $log = Net::TcpDumpLog->new(); 
$log->read("HBO.libpcap.pcap");

my $IPS      = {};
my $REPORT   = '';

foreach my $index ($log->indexes) { 
	my $eth_obj;
	my $eth_data;
	my $ip_obj;
	my $ip_data;
	my $tcp_obj;
	my $IP_src;
	my $IP_dest;
	my $IP_tos;
	my $IP_opt;

	my $URL   = '';
	my $HOST  = '';
	my $TYPE  = '';

	## Break it out
	my ($length_orig, $length_incl, $drops, $secs, $msecs) = $log->header($index); 
	my $data = $log->data($index);

	## ETHERNET
	$eth_obj = NetPacket::Ethernet->decode($data);
	# src_mac   -- The source MAC address for the ethernet packet as a hex string.
	# dest_mac  -- The destination MAC address for the ethernet packet as a hex string.
	# type      -- The protocol type for the ethernet packet.
	# data      -- The protocol type for the ethernet packet.

	$eth_data = sprintf('Type: %s',$eth_obj->{type});

	## IP 
	next unless $eth_obj->{type} == NetPacket::Ethernet::ETH_TYPE_IP;
	$ip_obj = NetPacket::IP->decode($eth_obj->{data});
	# ver      -- The IP version number of this packet.
	# hlen     -- The IP header length of this packet.
	# flags    -- The IP header flags for this packet.
	# foffset  -- The IP fragment offset for this packet.
	# tos      -- The type-of-service for this IP packet.
	# len      -- The length (including length of header) in bytes for this packet.
	# id       -- The identification (sequence) number for this IP packet.
	# ttl      -- The time-to-live value for this packet.
	# proto    -- The IP protocol number for this packet.
	# cksum    -- The IP checksum value for this packet.
	# src_ip   -- The source IP address for this packet in dotted-quad notation.
	# dest_ip  -- The destination IP address for this packet in dotted-quad notation.
	# options  -- Any IP options for this packet.
	# data     -- The encapsulated data (payload) for this IP packet.

	$IP_src    = $ip_obj->{src_ip}||'';
	$IP_dest   = $ip_obj->{dest_ip}||'';
	$IP_tos    = $ip_obj->{tos}||'';
	$IP_opt    = $ip_obj->{opt}||'';
	$ip_data   = sprintf('%s %s --> %s :: %s',$IP_tos,$IP_src,$IP_dest,$IP_opt);

	## TCP
	next unless $ip_obj->{proto} == NetPacket::IP::IP_PROTO_TCP;
	$tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
	# src_port      -- The source TCP port for the packet.
	# dest_port     -- The destination TCP port for the packet.
	# seqnum        -- The TCP sequence number for this packet.
	# acknum        -- The TCP acknowledgement number for this packet.
	# hlen          -- The header length for this packet.
	# reserved      -- The 6-bit "reserved" space in the TCP header.
	# flags         -- Contains the urg, ack, psh, rst, syn, fin, ece and cwr flags for this packet.
	# winsize       -- The TCP window size for this packet.
	# cksum         -- The TCP checksum.
	# urg           -- The TCP urgent pointer.
	# options       -- Any TCP options for this packet in binary form.
	# data          -- The encapsulated data (payload) for this packet.


	##  Find the HTTP Traffic
	#if ($tcp_obj->{data} =~ /GET|POST|get|post/) {	
		my $parts = token_data($tcp_obj->{data});
		## Write the record.
		$HOST = $parts->{host};
		$URL = sprintf('http://%s%s',$parts->{host},$parts->{uri})  if $parts->{host};
		$IPS->{sprintf("GetPost: %s -> %s",$IP_src,$IP_dest)} = sprintf('"%s","%s","%s","%s"',$IP_src,$HOST,$ip_data,$URL);
	#}
	#else {
	#	my $stuff = bin2asc($tcp_obj->{data});
	#	$IPS->{sprintf("Other: %s -> %s",$IP_src,$IP_dest)} = sprintf('"%s","%s","%s","%s"',$IP_src,'',$ip_data,$stuff);
	#}

	next unless $URL;

	#if($URL =~ /mp4/){
		## Determine traffic direction
		if($IP_src =~ /^192\.168\./){
			# Push to OUTBOUND
			printf '"%s","%s","%s","%s"%s',$IP_dest,$HOST,$URL,$TYPE,"\n";
			#printf "%s|%s|%s|%s\n",$IP_dest,$HOST,$URL,$TYPE;
			#push @$OUTBOUND,sprintf('"%s","%s","%s","%s"',$IP_dest,$HOST,$URL,$TYPE) if $HOST;
		}
		else {
			# Push to INBOUND
			printf '"%s","%s","%s","%s"%s',$IP_src,$HOST,$URL,$TYPE,"\n";
			#printf "%s|%s|%s|%s\n",$IP_src,$HOST,$URL,$TYPE;
			#push @$INBOUND,sprintf('"%s","%s","%s","%s"',$IP_src,$HOST,$URL,$TYPE) if $HOST;
		}
	#}

	#last if $URL;
#  
#	print "\t", $ip_obj->{src_ip}, ":", $tcp_obj->{src_port}, " -> ", $ip_obj->{dest_ip}, ":", $tcp_obj->{dest_port}, "\n";
#	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($secs + $msecs/1000);
#	printf("%02d-%02d %02d:%02d:%02d.%d", $mon, $mday, $hour, $min, $sec, $msecs), " ", $eth_obj->{src_mac}, " -> ", $eth_obj->{dest_mac}, "\n";    
}

#printf("======== INBOUND TRAFFIC ========\n%s\n",Dumper $INBOUND);
#printf("======== OUTBOUND TRAFFIC =======\n%s\n",Dumper $OUTBOUND);
#printf("=================================\n");
#printf("IPS: %s\n",Dumper $IPS);

exit;

##  subs

sub token_data {
	my $data  = shift;
	#-# printf("HTTP DATA =======\n %s \n========\n",$data);
	my @items = split (/\n|\r\n|\r/,$data);
	my $item;

	my $host  = '';
	my $uri   = '';
	my $agent = '';
	foreach $item (@items) {
		if ($item =~ /GET\s+(.*)\s+HTTP.*/) {
			$uri= $1;
		}
		if ($item =~ /Host:\s+(.*)/) {
			$host = $1;
		}
		if ($item =~ /User-Agent:\s+(.*)/) {
			$agent = $1;
			$agent =~ s/\(//g;
			$agent =~ s/\)//g;
		}
	}

	return {host=>$host,uri=>$uri,agent=>$agent};
}


sub bin2asc {
	@_ = split ' ', $_[0] if @_ == 1;
	my @chars;
	for (@_) {
		my $asc = unpack "C", pack "B8", $_;
		push @chars, chr($asc);
	}
	return wantarray ? @chars : join "", @chars;
}

