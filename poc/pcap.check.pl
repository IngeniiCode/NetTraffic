#!/usr/bin/perl 
use strict;
use warnings;
$| = 1;

use Getopt::Std;
use Net::Pcap;
use NetPacket::ARP qw(:ALL);
use NetPacket::Ethernet qw(:ALL);
use NetPacket::ICMP qw(:ALL);
use NetPacket::IGMP qw(:ALL);
use NetPacket::IP qw(:ALL);
use NetPacket::TCP qw(:ALL);
use NetPacket::UDP qw(:ALL);
use Socket;
use Net::DNS;
use Switch;
use Data::Dumper;
use Excel::Writer::XLSX;
# ===============================
my $DISABLED          = 0;
my $ENABLED           = 1;
my $READ_ALL_PKTS     = -1;
my $DEFAULT_LIST_SIZE = 10;
my $UNKNOWN_ERROR     = -1;
my $PROGRAM_NAME      = 'pcap.analysis.pl';
my $WSformat          = {};
my $max_list_size     = $DEFAULT_LIST_SIZE;
# ===============================
my $DNS       = {};
my $URLS      = {};
my $IPS       = {};
my $MEDIA     = {};
my $MAPS      = {};
my $REC       = {};
my $FRAMES    = ();
my $currframe = 0;
my %pcap_stat = ();
my $file      = $ARGV[0];
# ===============================

my $error;
my $pcap = pcap_open_offline( $file, \$error ) || die( __LINE__,  "Can't read $file: " );
my $datalink_type = pcap_datalink($pcap);

# +
# +  Loop through the pcap data, shove data down callback pipe 'process_pcap()'
# +
pcap_loop( $pcap, -1, \&process_pcap, $datalink_type );

# +  close loop / end
pcap_close($pcap);

write_spreadsheet();

#process_stats();

#printf("=======  DNS  ======\n%s\n",Dumper $DNS);
#printf("=======  URLS  ======\n%s\n",Dumper $URLS);
#printf("=======  IPs ======\n%s\n",Dumper $IPS);
printf("=======  FRAMES  [%d] ======\n",scalar(keys %$FRAMES));
print Dumper $FRAMES;
#printf("=======  MAPS  ======\n%s\n",Dumper $MAPS);

# +
# +  // END
# +
exit;


# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Sub Routines
# +
# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# +
# +   Process a PCAP frame
# +
sub process_pcap {
	my ( $type, $header, $raw ) = @_;
	my $type_name = pcap_datalink_val_to_name($type);
	my $timestamp = $header->{tv_sec};
printf("HEADER %s\n",Dumper $header);
	exit;
	my $id = $currframe = $pcap_stat{pkts}++;  #  Keep raw packet count

	#
	# Capture Start and End time frames
	#
	if ( !$pcap_stat{start_time} || $timestamp < $pcap_stat{start_time} ) {
		$pcap_stat{start_time} = $timestamp;
		$REC->{start_time} = $timestamp;
	}
	if ( !$pcap_stat{stop_time} || $timestamp > $pcap_stat{stop_time} ) {
		$pcap_stat{stop_time} = $timestamp;
		$REC->{stop_time} = $timestamp;
	}

	#
	#  Hand off packet for processing
	switch($type) {
		case DLT_EN10MB    { parse_packet($raw); }   #  This is the entry point!!
		else               { warn "No parser for datalink: $type_name\n"; }
	}


	return;
}

# +
# +  Packet Processing
# +
sub parse_packet {
	my $pkt      = NetPacket::Ethernet->decode(shift);
	my $pkt_data = $pkt->{data};  # $payload contains the actual message
	my $id       = $currframe;
	my $pkt_type = '';

	$REC = {};  # clear out the record

	switch( $pkt->{type} ) {
		case ETH_TYPE_IP        { $pkt_type = 'IP'; }
		case ETH_TYPE_ARP       { $pkt_type = 'ARP'; }
		case ETH_TYPE_APPLETALK { $pkt_type = 'APPLETALK'; }
		case ETH_TYPE_SNMP      { $pkt_type = 'SNMP'; }
		case ETH_TYPE_IPv6      { $pkt_type = 'IPv6'; }
		case ETH_TYPE_PPP       { $pkt_type = 'PPP'; }
		else                    { $pkt_type = 'other'; }
	}

#	printf("===========  FRAME ID: %d [%s]  =========\n",$id,$pkt_type);

	$pcap_stat{enet}{type}{$pkt_type}++;
	$REC->{pkt_type} = $pkt_type;
	$REC->{MAC} = {
		src_mac  => $pkt->{src_mac},
		dest_mac => $pkt->{dest_mac}
	};
	
	#
	#  Call the IP Handler on Payload
	#
	switch( $pkt->{type} ) {
		case ETH_TYPE_IP        { 
			# Process IP Packets only.
			my $decoded = NetPacket::IP->decode($pkt_data);
			my $proto   = $decoded->{proto} || 0;
			my $payload = parse_ip($decoded);
			switch( $proto ) {
				case IP_PROTO_ICMP    { 
					$pcap_stat{ip}{proto}{ICMP}++;
	                                parse_icmp($payload); }
				case IP_PROTO_TCP     { 
					$pcap_stat{ip}{proto}{TCP}++;
                                	parse_tcp($payload); }
				case IP_PROTO_UDP     { 
					$pcap_stat{ip}{proto}{UDP}++;
                                	parse_udp($payload); }
        			else                  { 
					$pcap_stat{ip}{proto}{other}++; }
			};
		}
		else                    {}
	}

	$FRAMES->{$id} = $REC;

	return;
}

# +
# +   IP  Packet Processing
# +
# +   Routes the processing to the various parsers
# +   for further interogation
# +
sub parse_ip {
	my $pkt      = shift;
	my $payload  = $pkt->{data};
	my $show     = 0;
	my $id       = $currframe;

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

	$pcap_stat{ip}{pkts}++;

	$pcap_stat{ip}{srcaddr}{ $pkt->{src_ip} || 0  }++;
	$pcap_stat{ip}{dstaddr}{ $pkt->{dest_ip} || 0 }++;
   
	#  Save the data 
	$REC->{IP} = {
		src  => $pkt->{src_ip}  || -1,
		dest => $pkt->{dest_ip} || -1,
		len  => $pkt->{len},  # length
	};

	# Record some stats
	switch( $pkt->{len} ) {
		case { $_[0] <= 64   }   { $pcap_stat{ip}{length}{'<=64'  }++; }
		case { $_[0] <= 128  }   { $pcap_stat{ip}{length}{'<=128' }++; }
		case { $_[0] <= 512  }   { $pcap_stat{ip}{length}{'<=512' }++; }
		case { $_[0] <= 1024 }   { $pcap_stat{ip}{length}{'<=1024'}++; }
		case { $_[0] <= 1500 }   { $pcap_stat{ip}{length}{'<=1500'}++; }
		else                     { $pcap_stat{ip}{length}{'>1500' }++; }
	}

	return $payload;
}

# +
# +  ICMP  Packate Processing
# +
sub parse_icmp {
	my $pkt = NetPacket::ICMP->decode(shift);
	my $id  = $currframe;
	my $type = 

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

	$pcap_stat{icmp}{pkts}++;

	switch( $pkt->{type} ) {
		case ICMP_ECHOREPLY      { $type = 'echo_reply'; }
		case ICMP_UNREACH        { $type = 'unreachable'; }
		case ICMP_SOURCEQUENCH   { $type = 'source_quench'; }
		case ICMP_REDIRECT       { $type = 'redirect'; }
		case ICMP_ECHO           { $type = 'echo'; }
		case ICMP_ROUTERADVERT   { $type = 'router_advert'; }
		case ICMP_ROUTERSOLICIT  { $type = 'router_solicit'; }
		case ICMP_TIMXCEED       { $type = 'time_exceeded'; }
		case ICMP_PARAMPROB      { $type = 'parameter_prob'; }
		case ICMP_TSTAMP         { $type = 'timestamp'; }
		case ICMP_TSTAMPREPLY    { $type = 'tstamp_reply'; }
		case ICMP_IREQ           { $type = 'info_request'; }
		case ICMP_IREQREPLY      { $type = 'info_reply'; }
		case ICMP_MASKREQ        { $type = 'mask_request'; }
		case ICMP_MASKREPLY      { $type = 'mask_reply'; }
		else                     { $type = 'other'; }
	}

	$pcap_stat{icmp}{type}{$type}++;
	$REC->{ICMP} = {
		type   =>  $type
	};

	# save frames data	

#	printf("%s FRAME: %s\t TYPE:(%s)\n",(caller(0))[3],$id,$pkt->{type});

	return;
}

# +
# +   TCP Packet Processing
# +
sub parse_tcp {
	my $pkt     = NetPacket::TCP->decode(shift);
	my $payload = $pkt->{data};
	my $show    = 0;
	my $id      = $currframe;

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

#	printf("%s FRAME: %s\nPAYLOAD: %s\n",(caller(0))[3],Dumper $REC,$payload);

	$pcap_stat{tcp}{pkts}++;
	$pcap_stat{tcp}{src_port}{ $pkt->{src_port} }++;
	$pcap_stat{tcp}{dst_port}{ $pkt->{dest_port} }++;

	switch( $pkt->{flags} ) {
		case { $_[0] & FIN }  { $pcap_stat{tcp}{flags}{FIN}++; next; }
		case { $_[0] & SYN }  { $pcap_stat{tcp}{flags}{SYN}++; next; }
		case { $_[0] & RST }  { $pcap_stat{tcp}{flags}{RST}++; next; }
		case { $_[0] & PSH }  { $pcap_stat{tcp}{flags}{PSH}++; next; }
		case { $_[0] & ACK }  { $pcap_stat{tcp}{flags}{ACK}++; next; }
		case { $_[0] & URG }  { $pcap_stat{tcp}{flags}{URG}++; next; }
		case { $_[0] & ECE }  { $pcap_stat{tcp}{flags}{ECE}++; next; }
		case { $_[0] & CWR }  { $pcap_stat{tcp}{flags}{CWR}++; next; }
	}

	$REC->{TCP} = {
		src_ip   => $REC->{IP}{src} || -1,
		src_port => $pkt->{src_port} || -1,
		dest_ip  => $REC->{IP}{dest} || -1,

		dst_port => $pkt->{dest_port} || -1,
		seqnum   => $pkt->{seqnum},
		acknum   => $pkt->{acknum},
	};

    # --  hand off packet to HTTP parser for further exam. 
    if ( $pkt->{dest_port} == 80 || $pkt->{src_port} == 80 ) {
    	$REC->{req_type}  = 'http';
        return parse_http('http',$payload);
    }

    # --  hand off packet to HTTPS parser for further exam. 
    if ( $pkt->{dest_port} == 443 || $pkt->{src_port} == 443 ) {
    	$REC->{req_type}  = 'https';
        return parse_http('https',$payload);
    }

    # --  hand off packet to DNS parser for further exam. 
    if ( $pkt->{dest_port} == 53 || $pkt->{src_port} == 53 ) {
    	$REC->{req_type}  = 'dns';
        return parse_dns( $payload );
    }

    # --  hand off packet to IP parser for further exam. 
    $REC->{req_type}  = 'tcp/ip';
    return parse_tcpip( $payload );

    return; #printf("SRC_PORT:[%d]\tDEST_PORT:[%d]\tNO PARSE ATTEMPTED\n",$pkt->{src_port},$pkt->{dest_port});
}

# +
# +   UDP Packet Processing
# +
sub parse_udp {
    my $pkt     = NetPacket::UDP->decode(shift);
    my $payload = $pkt->{data};

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

#	printf("%s PAYLOAD: %s\n",(caller(0))[3],$payload);

    $pcap_stat{udp}{pkts}++;
    $pcap_stat{udp}{src_port}{ $pkt->{src_port} }++;
    $pcap_stat{udp}{dst_port}{ $pkt->{dest_port} }++;

    # --  hand off packet to DNS parser for further exam. 
    if ( $pkt->{dest_port} == 53 || $pkt->{src_port} == 53 ) {
        parse_dns( $payload );
    }

    return;
}

# +
# +  DNS Packet Processing
# +
sub parse_dns { 
	my $pkt = shift;
	my $dns = Net::DNS::Packet->new(\$pkt);
	my $id      = $currframe;

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

	return if !defined $dns;

	my $header   = $dns->header;
	my @question = $dns->question;
	my @answer   = $dns->answer;

    # -  general stats collection
    $pcap_stat{dns}{pkts}++;
    $pcap_stat{dns}{opcode}{ $header->opcode }++;
    $pcap_stat{dns}{rcode}{ $header->rcode }++;

    $pcap_stat{dns}{aa}++ if $header->aa;
    $pcap_stat{dns}{ra}++ if $header->ra;
    $pcap_stat{dns}{rd}++ if $header->rd;
    $pcap_stat{dns}{tc}++ if $header->tc;
    $pcap_stat{dns}{cd}++ if $header->cd;
    $pcap_stat{dns}{ad}++ if $header->ad;
    $pcap_stat{dns}{qr}++ if $header->qr;

	for my $ans (@answer) {
		if($ans->string =~ /([a-z0-9\._-]+)\.\t.*\tIN\tA\t(\d+\.\d+\.\d+\.\d+)$/i){
			my $hostname = $1||'';
			my $ip       = $2||'';
			$DNS->{HOST_to_IP}{$hostname}  = $ip;
			$DNS->{IP_to_HOST}{$ip}        = $hostname;
			$REC->{DNS} = {
            			hostname => $hostname,
				ip       => $ip,
			};
		}
	}

	# store fram data if set

        for my $ques (@question) {
            $pcap_stat{dns}{qname}{ $ques->qname }++;
        }

    return;
}

# +
# +  HTTP Packet Processing
# +
sub parse_http {
	my ($prefix,$data) = @_;
	my $id      = $currframe;

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

	my $parts = token_httpd($data);
	## Save the record.
	my $host = $parts->{host};
	my $uri  = $parts->{uri};
	$parts->{URL} = sprintf('%s://%s%s',$prefix,$host,$uri) if $uri;
        $REC->{HTTPD} = $parts if $uri;
printf("SAVED PARTS: %s\n",Dumper $parts);
	$URLS->{$parts->{URL}} = $parts if $host;
	return;
} 

# +
# +  TCP/IP Packet Processing
# +
sub parse_tcpip {
	my ($data) = @_;
	my $id     = $currframe;
	my $parts  = token_tcpip($data);

	# - - - - - - - - - - - - - - - - - - 
	$REC->{last_parser} = (caller(0))[3];
	# - - - - - - - - - - - - - - - - - - 

	printf("%s FRAME:[%d]\n%s\n",(caller(0))[3],$id,,Dumper $parts);
	## Write the record.
	$IPS->{$id} = $parts if $parts->{ip_addr};

	return;
} 

# +
# + Write the Spreadshet 
# +
sub write_spreadsheet {

	# Create a new Excel workbook
	my $WB = Excel::Writer::XLSX->new( sprintf('%s.xlsx',$file) );

	$WB->set_properties(
        	title    => sprintf('%s Network Analysis Report',$file),
		author   => 'David DeMartini  fbo  Appdetex.com',
		comments => 'Automated Network Traffic Analysis',
	);
	# Define WorkBook formatting
	$WSformat->{bold}   = $WB->add_format( bold => 1);
	$WSformat->{header} = $WB->add_format( bold => 1);
	$WSformat->{title}  = $WB->add_format( bold => 1);
	$WSformat->{normal} = $WB->add_format( bold => 0);

	# Add Metrics
	add_summary_worksheet($WB);

	# Add HTTP Worksheet
	add_http_worksheet($WB);

	# Add DNS Worksheet 
	add_dns_worksheet($WB);

	# Close and Save
	$WB->close();

	return;
}

# +
# + HTTP Worksheet 
# +
sub add_http_worksheet {
	my $workbook = shift;
	my $row_st       = 2;
	my $col_st       = 0;
	my $rows         = 0;

	# define formatting
	# Instanciate Workbook
	my $http_ws = $workbook->add_worksheet( 'URLs' ); 
	#$http_ws->set_tab_color(0x35);
	$http_ws->set_tab_color('orange');
	#$http_ws->set_tab_color(40,255,102,0);  # Orange

	# set column widths
	$http_ws->set_column(0,0,12);
	$http_ws->set_column(1,1,30);
	$http_ws->set_column(2,2,15);
	$http_ws->set_column(3,3,115);

	# Headers
	$http_ws->merge_range(0,0,0,4,'',$WSformat->{bold});
	$http_ws->write_string(0,0,"HTTP Traffic",$WSformat->{bold});
	
	$http_ws->write_string(1,0,"IP Address",$WSformat->{bold});
	$http_ws->write_string(1,1,"Hostname",$WSformat->{bold});
	$http_ws->write_string(1,2,"Content-Type",$WSformat->{bold});
	$http_ws->write_string(1,3,"URL",$WSformat->{bold});
	
	for my $key ( sort {$URLS->{$b} - $URLS->{$a}} keys %$URLS ) { 
		my $host = $URLS->{$key}{host};
		my $ip   = get_host_ip($host);
		my $url  = $URLS->{$key}{URL};
		my $uri  = $URLS->{$key}{uri};
		my $type = ($URLS->{$key}{type}) ? $URLS->{$key}{type} : guess_type($uri);
		$http_ws->write_string($row_st+$rows,$col_st,$ip||'',$WSformat->{normal});
		$http_ws->write_string($row_st+$rows,$col_st+1,$host||'',$WSformat->{normal});
		$http_ws->write_string($row_st+$rows,$col_st+2,$type||'',$WSformat->{normal});
		$http_ws->write_string($row_st+$rows,$col_st+3,$url||'',$WSformat->{normal});
		$rows++;
		# check to see if uri has a matching media codec
#		if(my $media_type = check_for_media($uri)){
#			# matches some media filename suffixes.
#			$MEDIA->{$url} = {
#				host  =>  $host,
#				ip    =>  $ip,
#				type  =>  $media_type,
#				url   =>  $url
#			};
#		}
	}

	return;
}

# +
# + DNS Workshet 
# +
sub add_dns_worksheet {
	my $workbook = shift;

	# define formatting
	my $dns_ws = $workbook->add_worksheet( 'DNS Traffic' ); 
	$dns_ws->set_tab_color('blue');
	
	# Set column widths
	$dns_ws->set_column(0,0,35);  # set witch to 40
	$dns_ws->set_column(1,1,15);  # set witch to 15

	# Add headers
	$dns_ws->write_string( 0, 0, 'Hostname', $WSformat->{header});
	$dns_ws->write_string( 0, 1, 'IP Address', $WSformat->{header});

	# Add the Hostname Translation  cols A & B
	my $HOSTS =  $DNS->{HOST_to_IP};
	my $IPS   =  $DNS->{IP_to_HOST};
	my $host_row = 1;
	foreach my $ip (keys %$IPS) {
		$dns_ws->write_string( $host_row, 0, $IPS->{$ip} );
		$dns_ws->write_string( $host_row, 1, $ip );
		$host_row++;
	}

	# $worksheet->write_string( 0, 0, 'Your text here' );

	return;
}

# +
# + Write the Spreadshet 
# +
sub add_summary_worksheet {
	my ($workbook) = @_;

	# init workbook
	my $sum_ws = $workbook->add_worksheet( 'Summary' ); 
	$sum_ws->set_tab_color( 0x3 );

	print_summary($sum_ws);
	print_ip($sum_ws);

	return;
}


# +
# +  Stats
# +
sub process_stats {

    #print_header();

    if ( defined $pcap_stat{pkts} ) {
        #print_summary();
        #print_enet();
    }

    if ( defined $pcap_stat{ip}{pkts} ) {
        #print_ip();
    }

    if ( defined $pcap_stat{icmp}{pkts} ) {
        #print_icmp();
    }

    if ( defined $pcap_stat{igmp}{pkts} ) {
        #print_igmp();
    }

    if ( defined $pcap_stat{tcp}{pkts} ) {
        #print_tcp();
    }

    if ( defined $pcap_stat{udp}{pkts} ) {
        #print_udp();
    }

    if ( defined $pcap_stat{dns}{pkts} ) {
        #print_dns();
    }

    return;
}

# +
# +   Header
# +
sub print_header {
    print "# $PROGRAM_NAME\n";
    print "\n";
    return;
}

# +
# +   Summary Generation
# +
sub print_summary {
	my ($sum_ws) = @_;
	my $start_time;
	my $stop_time;

	# Set column widths
	$sum_ws->set_column(0,0,9);
	$sum_ws->set_column(1,2,10);
	$sum_ws->set_column(3,3,2);
	$sum_ws->set_column(4,4,9);
	$sum_ws->set_column(5,6,10);

	# Add header
	$sum_ws->merge_range(0,0,0,14,'',$WSformat->{bold});
	$sum_ws->write_string(0,0,"Summary - $file",$WSformat->{bold});

	# Add frames summary
	$sum_ws->merge_range(1,1,1,3,'',$WSformat->{normal});
	$sum_ws->write_string(1,0,"Frames",$WSformat->{bold});
	$sum_ws->write_string(1,1,$pcap_stat{pkts},$WSformat->{normal});

	$start_time = gmtime( $pcap_stat{start_time} );
	$stop_time  = gmtime( $pcap_stat{stop_time} );

	# Add Timimng
	$sum_ws->write_string(2,0,"Start time",$WSformat->{bold});
	$sum_ws->merge_range(2,1,2,3,'',$WSformat->{normal});
	$sum_ws->write_string(2,1,$start_time,$WSformat->{normal});	
	$sum_ws->write_string(3,0,"Stop time",$WSformat->{bold});
	$sum_ws->merge_range(3,1,3,3,'',$WSformat->{normal});
	$sum_ws->write_string(3,1,$stop_time,$WSformat->{normal});	

    return;
}

# +
# +   ENET Packet Processing
# +
sub print_enet {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %type         = %{ $pcap_stat{enet}{type} };

    print "# Ethernet Types\n";

    ETYPE:
    for $value ( sort {$type{$b} - $type{$a}} keys %type ) {
        $list_counter++;
        printf "%-6s\t%s\n", $value, $type{$value};
        last ETYPE if $list_counter == $max_list_size;
    }

    print "\n";

    return;
}

# +
# +   IP Packet Processing
# +
sub print_ip {
	my ($sum_ws)     = @_;
	my $value;       # generic hash value placeholder in for loops
	my $list_counter = 0;
	my %length       = %{ $pcap_stat{ip}{length} };
	my %proto        = %{ $pcap_stat{ip}{proto} };
	my $row_st       = 7;
	my $col_st       = 0;
	my $src_rows     = 0;  # total srource rows
	my $dest_rows    = 0;  # total destination rows
	my $dta_rows     = 0;  # total number of datasize rows
	my $prot_rows    = 0;  # total number of protocol rows
	my $max_rows     = 0;  # total number of row sections written

	# set length to zero if undef, because gaps in output may be confusing
	$length{'<=64'  } ||= 0;
	$length{'<=128' } ||= 0;
	$length{'<=512' } ||= 0;
	$length{'<=1024'} ||= 0;
	$length{'<=1500'} ||= 0;
	$length{'>1500' } ||= 0;

	$sum_ws->merge_range(5,0,5,14,'',$WSformat->{bold});
	$sum_ws->write_string(5,0,'Internet Protocol Metrics',$WSformat->{bold});
	$sum_ws->write_string(6,0,'IP datagrams',$WSformat->{bold});
	$sum_ws->write_string(6,1,$pcap_stat{ip}{pkts},$WSformat->{normal});

	#
	# Source IP Data
	#
	$row_st = 8;
	$col_st = 0;
	$sum_ws->merge_range($row_st,$col_st,$row_st,$col_st+2,'',$WSformat->{bold});
	$sum_ws->write_string($row_st,$col_st,'Source IP addresses',$WSformat->{bold});

	$row_st++;
	$col_st++;
	$sum_ws->write_string($row_st+$src_rows,$col_st,'IP Address',$WSformat->{bold});
	$sum_ws->write_string($row_st+$src_rows,$col_st+1,'Packets',$WSformat->{bold});
	
	$row_st++;
        my %srcaddr = %{ $pcap_stat{ip}{srcaddr} };
        for $value ( sort {$srcaddr{$b} - $srcaddr{$a}} keys %srcaddr ) {
	    $sum_ws->write_string($row_st+$src_rows,$col_st,$value,$WSformat->{normal});
	    $sum_ws->write_string($row_st+$src_rows,$col_st+1,$srcaddr{$value},$WSformat->{normal});
            $src_rows++;
        }
	$max_rows = ($max_rows > $src_rows) ? $max_rows : $src_rows;

	#
	# Destination IP Data
	#
	$row_st = 8;
	$col_st = 4;
	$sum_ws->merge_range($row_st,$col_st,$row_st,$col_st+2,'',$WSformat->{bold});
	$sum_ws->write_string($row_st,$col_st,'Destination IP addresses',$WSformat->{bold});
        
	$row_st++;
	$col_st++;
	$sum_ws->write_string($row_st+$dest_rows,$col_st,'IP Address',$WSformat->{bold});
	$sum_ws->write_string($row_st+$dest_rows,$col_st+1,'Packets',$WSformat->{bold});
	
	$row_st++;
        my %dstaddr = %{ $pcap_stat{ip}{dstaddr} };
        for $value ( sort {$dstaddr{$b} - $dstaddr{$a}} keys %dstaddr ) {
	    $sum_ws->write_string($row_st+$dest_rows,$col_st,$value,$WSformat->{normal});
	    $sum_ws->write_string($row_st+$dest_rows,$col_st+1,$dstaddr{$value},$WSformat->{normal});
            $dest_rows++;
        }
	$max_rows = ($max_rows > $dest_rows) ? $max_rows : $dest_rows;

	#
	# Total Datagram Lengths 
	#
	$row_st = 8;
	$col_st = 8;
	$sum_ws->merge_range($row_st,$col_st,$row_st,$col_st+2,'',$WSformat->{bold});
	$sum_ws->write_string($row_st,$col_st,'Total Datagram Lengths',$WSformat->{bold});
	
	$row_st++;
	$col_st++;
	$sum_ws->write_string($row_st+$dta_rows,$col_st,'Size',$WSformat->{bold});
	$sum_ws->write_string($row_st+$dta_rows,$col_st+1,'Packets',$WSformat->{bold});
	
	$row_st++;
        for $value ( sort {$length{$b} - $length{$a}} keys %length ) {
	    $sum_ws->write_string($row_st+$dta_rows,$col_st,$value,$WSformat->{normal});
	    $sum_ws->write_string($row_st+$dta_rows,$col_st+1,$length{$value},$WSformat->{normal});
            $dta_rows++;
        }
	$max_rows = ($max_rows > $dta_rows) ? $max_rows : $dta_rows;

	#
	#  IP protocols 
	#
	$row_st = 8;
	$col_st = 12;
	$sum_ws->merge_range($row_st,$col_st,$row_st,$col_st+2,'',$WSformat->{bold});
	$sum_ws->write_string($row_st,$col_st,'IP Protocols',$WSformat->{bold});
	
	$row_st++;
	$col_st++;
	$sum_ws->write_string($row_st+$prot_rows,$col_st,'Protocol',$WSformat->{bold});
	$sum_ws->write_string($row_st+$prot_rows,$col_st+1,'Packets',$WSformat->{bold});
	
	$row_st++;
	for $value ( sort {$proto{$b} - $proto{$a}} keys %proto ) {
	    $sum_ws->write_string($row_st+$prot_rows,$col_st,$value,$WSformat->{normal});
	    $sum_ws->write_string($row_st+$prot_rows,$col_st+1,$proto{$value},$WSformat->{normal});
            $prot_rows++;
        }
	$max_rows = ($max_rows > $prot_rows) ? $max_rows : $prot_rows;

	# determine longest section
	
    return $max_rows;
}

# +
# +  ICMP Packet Processing
# +
sub print_icmp {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %type         = %{ $pcap_stat{icmp}{type} };

    print "# Internet Control Message Protocol\n";
    print "ICMP messages: $pcap_stat{icmp}{pkts}\n";

    print "# ICMP types\n";

    TYPE:
    for $value ( sort {$type{$b} - $type{$a}} keys %type ) {
        $list_counter++;
        printf "%-15s\t%s\n", $value, $type{$value};
        last TYPE if $list_counter == $max_list_size;
    }

    print "\n";

    return;
}

# +
# +  IGMP Packet Processing
# +
sub print_igmp {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %type         = %{ $pcap_stat{igmp}{type} };
    my %grpaddr     = %{ $pcap_stat{igmp}{grpaddr} };

    print "# Internet Group Management Protocol\n";
    print "IGMP messages: $pcap_stat{igmp}{pkts}\n";

    print "# IGMP types\n";

    TYPE:
    for $value ( sort {$type{$b} - $type{$a}} keys %type ) {
        $list_counter++;
        printf "%-7s\t%s\n", $value, $type{$value};
        last TYPE if $list_counter == $max_list_size;
    }

    $list_counter = 0;

    print "# IGMP group addresses\n";

    GROUP_ADDR:
    for $value ( sort {$grpaddr{$b} - $grpaddr{$a}} keys %grpaddr ) {
        $list_counter++;
        printf "%-17s\t%s\n", $value, $grpaddr{$value};
        last GROUP_ADDR if $list_counter == $max_list_size;
    }

    print "\n";

    return;
}

# +
# +  TCP Packet Processing
# +
sub print_tcp {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %src_port     = %{ $pcap_stat{tcp}{src_port} };
    my %dst_port     = %{ $pcap_stat{tcp}{dst_port} };
    my %flags        = %{ $pcap_stat{tcp}{flags} };

    print "# Transmission Control Protocol\n";
    print "TCP segments: $pcap_stat{tcp}{pkts}\n";

    print "# TCP source ports\n";

    SRCPORT:
    for $value ( sort {$src_port{$b} - $src_port{$a}} keys %src_port ) {
        $list_counter++;
        printf "%-7s\t%s\n", $value, $src_port{$value};
        last SRCPORT if $list_counter == $max_list_size;
    }

    $list_counter = 0;

    print "# TCP destination ports\n";

    DSTPORT:
    for $value ( sort {$dst_port{$b} - $dst_port{$a}} keys %dst_port ) {
        $list_counter++;
        printf "%-7s\t%s\n", $value, $dst_port{$value};
        last DSTPORT if $list_counter == $max_list_size;
    }

    $list_counter = 0;

    print "# TCP flags\n";

    FLAGS:
    for $value ( sort {$flags{$b} - $flags{$a}} keys %flags ) {
        $list_counter++;
        printf "%-3s\t%s\n", $value, $flags{$value};
        last FLAGS if $list_counter == $max_list_size;
    }

    print "\n";

    return;
}

# +
# +  UDP Packet Processing
# +
sub print_udp {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %src_port      = %{ $pcap_stat{udp}{src_port} };
    my %dst_port      = %{ $pcap_stat{udp}{dst_port} };

    print "# User Datagram Protocol\n";
    print "UDP messages: $pcap_stat{udp}{pkts}\n";

    print "# UDP source ports\n";

    SRCPORT:
    for $value ( sort {$src_port{$b} - $src_port{$a}} keys %src_port ) {
        $list_counter++;
        printf "%-7s\t%s\n", $value, $src_port{$value};
        last SRCPORT if $list_counter == $max_list_size;
    }

    $list_counter = 0;

    print "# UDP destination ports\n";

    DSTPORT:
    for $value ( sort {$dst_port{$b} - $dst_port{$a}} keys %dst_port ) {
        $list_counter++;
        printf "%-7s\t%s\n", $value, $dst_port{$value};
        last DSTPORT if $list_counter == $max_list_size;
    }

    print "\n";

    return;
}

# +
# +  DNS  processing
# +
sub print_dns {
    my $value;       # generic hash value placeholder in for loops
    my $list_counter = 0;
    my %opcode       = %{ $pcap_stat{dns}{opcode} };
    my %rcode        = %{ $pcap_stat{dns}{rcode} };

    # set flags to zero if undef, because gaps in output may be confusing
    $pcap_stat{dns}{aa} ||= 0;
    $pcap_stat{dns}{ra} ||= 0;
    $pcap_stat{dns}{rd} ||= 0;
    $pcap_stat{dns}{tc} ||= 0;
    $pcap_stat{dns}{cd} ||= 0;
    $pcap_stat{dns}{ad} ||= 0;
    $pcap_stat{dns}{qr} ||= 0;

    print "# Domain Name System\n";
    print "DNS messages:         $pcap_stat{dns}{pkts}\n";
    print "Authoritative answer: $pcap_stat{dns}{aa}\n";
    print "Recursion available:  $pcap_stat{dns}{ra}\n";
    print "Recursion desired:    $pcap_stat{dns}{rd}\n";
    print "Truncated:            $pcap_stat{dns}{tc}\n";
    print "Checking desired:     $pcap_stat{dns}{cd}\n";
    print "Verified:             $pcap_stat{dns}{ad}\n";
    print "Query response:       $pcap_stat{dns}{qr}\n";

        my %qname        = %{ $pcap_stat{dns}{qname} };
        print "# DNS query names\n";

        QNAME:
        for $value ( sort {$qname{$b} - $qname{$a}} keys %qname ) {
            $list_counter++;
            # qname varies widely in string length, put that in 2nd column
            printf "%-12s\t%s\n", $qname{$value}, $value;
            last QNAME if $list_counter == $max_list_size;
        }

    print "\n";

    return;
}

# +
# +  token disassemble HTTP
# +
sub token_httpd {
        my ($data)  = @_;
        my @items = split (/\n|\r\n|\r/,$data);

	return {} unless $data;

        my $host  = '';
        my $uri   = '';
        my $agent = '';
	my $type  = '';

printf("HTTPD: %s\n",$data);

        foreach my $item (@items) {
                if ($item =~ /^GET\s+(.*)\s+HTTP\/1/) {
                        $uri= $1;
                }
                if ($item =~ /^POST\s+(.*)\s+HTTP\/1/) {
                        $uri= $1;
                }
                if ($item =~ /Content-Type:\s+(.*)/) {
                        $type = $1;
                }

                if ($item =~ /Host:\s+(.*)/) {
                        $host = trim_hostname($1);
                }
                if ($item =~ /User-Agent:\s+(.*)/) {
                        $agent = $1;
                        $agent =~ s/\(//g;
                        $agent =~ s/\)//g;
                }
        }

        return { host=>$host, uri=>$uri, type=>$type};
}

# +
# +  token disassemble HTTP
# +
sub token_tcpip {
        my ($data)  = @_;
        my @items = split (/\n|\r\n|\r/,$data);
	my $uri;
	my $host;
	my $type;
	my $agent;

printf("TCP/IP TRAFFIC: %s\n",$data);

        foreach my $item (@items) {
                if ($item =~ /Content-Type:\s+(.*)/) {
                        $type = $1;
                }

                if ($item =~ /Host:\s+(.*)/) {
                        $host = trim_hostname($1);
                }
                if ($item =~ /User-Agent:\s+(.*)/) {
                        $agent = $1;
                        $agent =~ s/\(//g;
                        $agent =~ s/\)//g;
                }
        }

        return { type=>$type, data=>$data };
}

# +
# +  try to determine media type
# +
sub guess_type {
	my($uri) = @_;
	
	# guess at content type if not defined --- this will need to be extended!!
	switch($uri) {
		case { $_[0] =~  /\.html?\b/i }      { return 'text/html'; }
		case { $_[0] =~  /\.js\b/i }         { return 'text/javascript'; }
		case { $_[0] =~  /\.jsp\b/i }        { return 'text/java-servelet'; }
		case { $_[0] =~  /\.asm\b/i }        { return 'text/x-asm'; }
		case { $_[0] =~  /\.asp\b/i }        { return 'application/asp'; }
		case { $_[0] =~  /\.php[3-6]?\b/i }  { return 'application/php'; }
		case { $_[0] =~  /\.cgi\b/i }        { return 'application/cgi'; }
		case { $_[0] =~  /\.do\b/i }         { return 'application/octet-stream'; }
		case { $_[0] =~  /\.ico\b/i }        { return 'image/icon'; }
		case { $_[0] =~  /\.png\b/i }        { return 'image/png'; }
		case { $_[0] =~  /\.json\b/i }       { return 'image/json'; }
		case { $_[0] =~  /\.jpeg\b/i }       { return 'image/jpeg'; }
		case { $_[0] =~  /\.jpg\b/i }        { return 'image/jpeg'; }
		case { $_[0] =~  /\.gif\b/i }        { return 'image/gif'; }
		case { $_[0] =~  /\.mp3\b/i }        { return 'audio/mp3'; }
		case { $_[0] =~  /\.avi\b/i }        { return 'video/avi'; }
		case { $_[0] =~  /\.mov\b/i }        { return 'video/mov'; }
		case { $_[0] =~  /\.mpeg\b/i }       { return 'video/mpeg'; }
		case { $_[0] =~  /\.mp4\b/i }        { return 'video/mp4'; }
		case { $_[0] =~  /\.mpg4\b/i }       { return 'video/mp4'; }
		case { $_[0] =~  /\.mpeg4\b/i }      { return 'video/mp4'; }
		else                                 { return '--'; }
	}

	return;
}

# +
# +  get hostname IP address(es)
# +
sub get_host_ip {
	my($host) = @_;
	return $DNS->{HOST_to_IP}{$host} if $DNS->{HOST_to_IP}{$host};
	my $ip = inet_ntoa(inet_aton($host));
	$DNS->{HOST_to_IP}{$host} = $ip;
	$DNS->{IP_to_HOST}{$ip} = $host unless $DNS->{IP_to_HOST}{$ip};
	return $DNS->{HOST_to_IP}{$host};
}

# +
# +  trim hostname 
# +
sub trim_hostname {
	my ($hostname) = @_;
	chomp($hostname);

	if($hostname =~ /([a-z0-9\-_\.]+):.*/i){
		return $1;
	}
	return $hostname;
}
	
1;
