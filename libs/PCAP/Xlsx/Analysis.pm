# =============================
  package Pcap::Xlsx::Analysis;
# =============================

use strict;
use Socket;
use Excel::Writer::XLSX;
use PCAP::GeoLocate;
use PCAP::Whois;
use Data::Dumper;
# - - - - - - - - - - - - - - - 
my $fmt    = {};
my $SUMMARY;
my $DNS    = {};  # local dns cache to speed processing
my $WHOIS  = {};  # local whois cache to speed processing
my $orig_file;

# XLSX Workbook Colors
#     8   =>   black
#     9   =>   white
#    10   =>   red
#    11   =>   lime
#    12   =>   blue
#    13   =>   yellow
#    14   =>   magenta
#    15   =>   cyan
#    16   =>   brown
#    17   =>   green
#    18   =>   navy
#    20   =>   purple
#    22   =>   silver
#    23   =>   gray
#    33   =>   pink
#    53   =>   orange

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  + 
# + + + + + + + + + + + + + + + + + + + +
sub new {
	my ($class,$file) = @_;

	my $outfile = sprintf('%s.v2b.xlsx',$file);	
	my $WB = Excel::Writer::XLSX->new($outfile);

        $WB->set_properties(
                title    => sprintf('%s Network Analysis Report',$file),
                author   => 'David DeMartini  fbo  Appdetex.com',
                comments => 'Automated Network Traffic Analysis',
        );
	
	# Define WorkBook formatting
	$fmt->{bold}   = $WB->add_format( bold => 1);
	$fmt->{header} = $WB->add_format( bold => 1);
	$fmt->{title}  = $WB->add_format( bold => 1);
	$fmt->{normal} = $WB->add_format( bold => 0, align => 'left', valign => 'top');
	$fmt->{wrap}   = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');



	# Add worksheets
#	$HTTPD = $WB->add_worksheet( 'HTTP Requests' );

	my $self  = { 
		outfile   => $outfile,
		orig_file => $file,
		WB        => $WB, 
		GEO       => new Pcap::GeoLocate,
		WHO       => new Pcap::Whois,
	};

	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  Write the Report 
# +
sub write_report {
	my($self,$data) = @_;

	# set the report data local
	$self->{REPORT} = $data;

	#$self->_summary();	
	$self->_media();
	$self->_dns();
	$self->_traffic_ip();
	#$self->_traffic_host();
	$self->_traffic_url();
	$self->_traffic_type();
	$self->_httpd();

	# Close and Save
	$self->{WB}->close();
	
}

# +
# +  Write HTTP Bi-Directional Media Information 
# +
sub _media {
	my($self) = @_;

	# localize hash refs to allows key iteration
	my $MEDIA  = $self->{REPORT}{MEDIA};
	my $FRAMES = $self->{REPORT}{FRAMES};

	return unless scalar(keys %$MEDIA );  # if there is nothing in that set, then don't add the tab

	my $OUTPUT = {};

	# ---  COLATE MEDIA RECORDS
	for my $id ( sort { $a <=> $b } keys %$MEDIA ) {
		next unless $FRAMES->{$id}{TYPE} eq 'HTTPD';  # looks like HTTPD traffic of some sort
		
		# ---  make record local
		my $rec = $FRAMES->{$id};

		# ---  get external edge of communication
		my $ip   = ($rec->{FLOW} eq 'OUTBOUND') ? $rec->{IP}{dest_ip} : $rec->{IP}{src_ip};
		
		# ---  aggregate traffic by  IP+URL
		my $key = sprintf('%s:%s:%s:%s',$ip,$rec->{HTTPD}{host}||'',$rec->{HTTPD}{url}||'',$rec->{HTTPD}{'Content-Type'}||'');
		$OUTPUT->{$key}{ip}   ||= $ip;
		$OUTPUT->{$key}{url}  ||= $rec->{HTTPD}{url};
		$OUTPUT->{$key}{host} ||= $rec->{HTTPD}{host};
		$OUTPUT->{$key}{type} ||= $rec->{HTTPD}{'Content-Type'};
		$OUTPUT->{$key}{size}  += $rec->{SIZE} || 0;
	}

	## Setup Outbound Report
	my $ws = $self->{WB}->add_worksheet( 'Media Detection' );
	$ws->merge_range(0,0,0,4,'',$fmt->{bold});
	$ws->write_string(0,0,' Media Detection ',$fmt->{bold});
	$ws->set_tab_color( 'red' );
	# Set column widths
	$ws->set_column(0,0,14);
	$ws->set_column(1,2,28);
	$ws->set_column(3,3,115);
	

	# Set column headers
	$ws->write_string(1,0,"IP",$fmt->{bold});
	$ws->write_string(1,1,"Hostname",$fmt->{bold});
	$ws->write_string(1,2,"Content-Type",$fmt->{bold});
	$ws->write_string(1,3,"URL",$fmt->{bold});
	$ws->write_string(1,5,"Whois Domain",$fmt->{bold});
	$ws->write_string(1,6,"Registrar",$fmt->{bold});
	$ws->write_string(1,7,"Registrant",$fmt->{bold});
	$ws->write_string(1,8,"Emails",$fmt->{bold});
	$ws->write_string(1,9,"DNS Servers",$fmt->{bold});
	
	my $row    = 2;
	my $col_st = 0;

	# ---  WRITE MEDIA RECORDS
	for my $id ( sort { $a <=> $b } keys %$OUTPUT ) {
		# ---  make record local
		my $rec = $OUTPUT->{$id};
		$ws->write_string($row,$col_st+0,$rec->{ip}||'',$fmt->{normal});
		$ws->write_string($row,$col_st+1,$rec->{host}||'',$fmt->{normal});
		$ws->write_string($row,$col_st+2,$rec->{type}||'',$fmt->{normal});
		# yes Exhell suppositly can only handle up to 255 chars in the 'url' cell --- lame
		(length($rec->{url}) > 254) ? $ws->write_string($row,$col_st+3,$rec->{url}||'',$fmt->{normal}) : $ws->write_url($row,$col_st+3,$rec->{url}||'',$fmt->{normal});
		$row++;
	}

	return;
}

# +
# +  Write HTTP Bi-Directional Information 
# +
sub _httpd {
	my($self) = @_;

	## Setup Outbound Report
	my $ws_out = $self->{WB}->add_worksheet( 'HTTP Requests' );
	$ws_out->merge_range(0,0,0,6,'',$fmt->{bold});
	$ws_out->write_string(0,0," HTTP OutBound Requests",$fmt->{bold});
	$ws_out->set_tab_color( 'blue' );
	# Set column widths
	$ws_out->set_column(0,1,6);
	$ws_out->set_column(2,2,14);
	$ws_out->set_column(3,3,30);
	$ws_out->set_column(4,4,20);
	$ws_out->set_column(5,5,115);

	# Set column headers
	$ws_out->write_string(1,0,"ID",$fmt->{bold});
	$ws_out->write_string(1,1,"Bytes",$fmt->{bold});
	$ws_out->write_string(1,2,"IP",$fmt->{bold});
	$ws_out->write_string(1,3,"Hostname",$fmt->{bold});
	$ws_out->write_string(1,4,"Content-Type",$fmt->{bold});
	$ws_out->write_string(1,5,"URL",$fmt->{bold});

	## Setup Inbound Report
	my $ws_in  = $self->{WB}->add_worksheet( 'HTTP Downloads' );
	$ws_in->merge_range(0,0,0,6,'',$fmt->{bold});
	$ws_in->write_string(0,0," HTTP Recieved / Downloaded Data",$fmt->{bold});
	$ws_in->set_tab_color( 'navy' );
	# Set column widths
	$ws_in->set_column(0,1,5);
	$ws_in->set_column(2,2,14);
	$ws_in->set_column(3,3,30);
	$ws_in->set_column(4,4,25);
	$ws_in->set_column(5,5,115);

	# Set column headers
	$ws_in->write_string(1,0,"ID",$fmt->{bold});
	$ws_in->write_string(1,1,"Bytes",$fmt->{bold});
	$ws_in->write_string(1,2,"IP",$fmt->{bold});
	$ws_in->write_string(1,3,"Hostname",$fmt->{bold});
	$ws_in->write_string(1,4,"Content-Type",$fmt->{bold});
	$ws_in->write_string(1,5,"URL",$fmt->{bold});

	my $in_row   = 2;
	my $out_row  = 2;

	# localize hash refs to allows key iteration
	my $FRAMES = $self->{REPORT}{FRAMES};
	for my $id ( sort { $a <=> $b } keys %$FRAMES ) {
		next unless $FRAMES->{$id}{TYPE} eq 'HTTPD';  # looks like HTTPD traffic of some sort
		# Filter out what looks like local addresses
		my $rec = $FRAMES->{$id};
		$rec->{ID}  = $id;
		if ($rec->{IP}{src_ip} =~ /192\.168\./){
			# outbound
			next unless $rec->{HTTPD}{host} || $rec->{HTTPD}{url} || $rec->{HTTPD}{'Content-Type'};  # drop if not any of these
			$rec->{row} = $out_row++;
			$rec->{ip} = $rec->{IP}{dest_ip};
			$self->_frame_rec($ws_out,$rec);
		}
		else {
			# inbound
			next unless $rec->{HTTPD}{host} || $rec->{HTTPD}{url} || $rec->{HTTPD}{'Content-Type'};  # drop if not any of these
			$rec->{row} = $in_row++;
			$rec->{ip} = $rec->{IP}{src_ip};
			$self->_frame_rec($ws_in,$rec);
		}	
	}
	return;
}

# +
# +  Write Frame Record 
# +
sub _frame_rec {
	my($self,$ws,$rec) = @_;
	
	my $row    = $rec->{row} || -1;  # if it's -1, there is a problem!!!
	my $col_st = $rec->{col} ||  0;  # this being zero is prefectly fine
	# -- data
	my $id    = $rec->{ID}                    || 0;
	my $bytes = $rec->{SIZE}                  || 0;
	my $ip    = $rec->{ip}                    || 'xxx.xxx.xxx.xxx';
	my $host  = $rec->{HTTPD}{host}           || $self->_get_ip_host($ip);
	my $url   = $rec->{HTTPD}{url}            || '';
	my $type  = $rec->{HTTPD}{'Content-Type'} || '';
	$ws->write_number($row,$col_st,$id||0,$fmt->{normal});
	$ws->write_number($row,$col_st+1,$bytes||'',$fmt->{normal});
	$ws->write_string($row,$col_st+2,$ip||'',$fmt->{normal});
	$ws->write_string($row,$col_st+3,$host||'',$fmt->{normal});
	$ws->write_string($row,$col_st+4,$type||'',$fmt->{normal});
	# yes Exhell suppositly can only handle up to 255 chars in the 'url' cell --- lame
	(length($url) > 254) ? $ws->write_string($row,$col_st+5,$url||'',$fmt->{normal}) : $ws->write_url($row,$col_st+5,$url||'',$fmt->{normal});

	return;
}

# +
# +  Write IP Traffic Information 
# +
sub _traffic_ip {
	my($self) = @_;

	my $ws  = $self->{WB}->add_worksheet( 'IP Inbound Traffic' );
	my $row_st = 2;
	my $row    = 0;
	my $col_st = 0;

	$ws->merge_range(0,0,0,10,'',$fmt->{bold});
	$ws->write_string(0,0,"Inbound TCP Traffic by IP",$fmt->{bold});

	$ws->set_tab_color( 'purple' );

	# localize hash refs to allows key iteration
	my $TRAFFIC_IP = $self->{REPORT}{TRAFFIC}{IP};
	
	# Set column widths
	$ws->set_column(0,0,9);
	$ws->set_column(1,1,13);
	$ws->set_column(2,2,9);
	$ws->set_column(3,3,35);
	$ws->set_column(4,4,4);
	# IP analysis info	
	$ws->set_column(5,8,35);

	$ws->write_string(1,0,"Bytes",$fmt->{bold});
	$ws->write_string(1,1,"IP Address",$fmt->{bold});
	$ws->write_string(1,2,"Port",$fmt->{bold});
	$ws->write_string(1,3,"Hostname",$fmt->{bold});	
	# IP analysis info	
	$ws->write_string(1,5,"Country",$fmt->{bold});
	$ws->write_string(1,6,"Organization",$fmt->{bold});
	$ws->write_string(1,7,"ISP",$fmt->{bold});
	$ws->write_string(1,8,"PTR-host",$fmt->{bold});
	
	for my $ip ( sort {$a <=> $b} keys %$TRAFFIC_IP ) {	
		# Filter out what looks like local addresses
		next if $ip =~ /192\.168\./;
		my $pData = $TRAFFIC_IP->{$ip};
		# collect up ISP data
		$self->{GEO}->go($ip);
		my $GeoInfo = $self->{GEO}->get_data();
		for my $port (keys %$pData) {
			my $bytes = $TRAFFIC_IP->{$ip}{$port}{bytes} ||0;
			my $host  = $self->{REPORT}{DNS}{IP_to_HOST}{$ip} || ' - unresolved -';
			$ws->write_number($row_st+$row,$col_st,$bytes||'',$fmt->{normal});
			$ws->write_string($row_st+$row,$col_st+1,$ip||'',$fmt->{normal});
			$ws->write_number($row_st+$row,$col_st+2,$port||'',$fmt->{normal});
			$ws->write_string($row_st+$row,$col_st+3,$host||'',$fmt->{normal});

			$ws->write_string($row_st+$row,$col_st+5,$GeoInfo->{country}||'',$fmt->{normal});
			$ws->write_string($row_st+$row,$col_st+6,$GeoInfo->{org}||'',$fmt->{normal});
			$ws->write_string($row_st+$row,$col_st+7,$GeoInfo->{isp}||'',$fmt->{normal});
			$ws->write_string($row_st+$row,$col_st+8,$GeoInfo->{host}||'',$fmt->{normal});

			$row++;
		}
	}

	return;
}

# +
# +  Write Host Traffic Information 
# +
sub _traffic_host {
	my($self) = @_;

	my $ws  = $self->{WB}->add_worksheet( 'Hostname Traffic' );
	my $row_st = 2;
	my $row    = 0;
	my $col_st = 0;

	$ws->merge_range(0,0,0,3,'',$fmt->{bold});
	$ws->write_string(0,0,"Traffic by Known Hostnames",$fmt->{bold});

	$ws->set_tab_color( 'magenta' );

	# localize hash refs to allows key iteration
	my $TRAFFIC_HOST = $self->{REPORT}{TRAFFIC}{HOSTS};

	# Set column widths
	$ws->set_column(0,0,7);
	$ws->set_column(1,0,35);

	$ws->write_string(1,0,"Bytes",$fmt->{bold});
	$ws->write_string(1,1,"Hostname",$fmt->{bold});	

	for my $host ( sort { $a <=> $b } keys %$TRAFFIC_HOST ) {
		# Filter out what looks like local addresses
		#next if $ip =~ /192\.168\./;
		my $bytes = $TRAFFIC_HOST->{$host}{bytes} ||0;
		$ws->write_number($row_st+$row,$col_st,$bytes||'',$fmt->{normal});
		$ws->write_string($row_st+$row,$col_st+1,$host||'',$fmt->{normal});
		$row++;
	}
	return;
}

# +
# +  Write URL Traffic Information 
# +
sub _traffic_url {
	my($self) = @_;

	my $ws  = $self->{WB}->add_worksheet( 'URL  Traffic' );
	my $row_st = 2;
	my $row    = 0;
	my $col_st = 0;

	$ws->merge_range(0,0,0,3,'',$fmt->{bold});
	$ws->write_string(0,0,"Traffic by named URL",$fmt->{bold});

	$ws->set_tab_color( 'cyan' );

	# localize hash refs to allows key iteration
	my $TRAFFIC_URL = $self->{REPORT}{TRAFFIC}{URLS};

	# Set column widths
	$ws->set_column(0,0,7);
	$ws->set_column(1,0,130);

	$ws->write_string(1,0,"Bytes",$fmt->{bold});
	$ws->write_string(1,1,"URL",$fmt->{bold});	

	for my $url ( keys %$TRAFFIC_URL ) {
		# Filter out what looks like local addresses
		#next if $ip =~ /192\.168\./;
		$url ||= ' - inbound w/o URL -';
		my $bytes = $TRAFFIC_URL->{$url}{bytes} ||0;
		$ws->write_number($row_st+$row,$col_st,$bytes||0,$fmt->{normal});
		(length($url) > 254) ? $ws->write_string($row_st+$row,$col_st+1,$url||'',$fmt->{normal}) : $ws->write_url($row_st+$row,$col_st+1,$url||'',$fmt->{normal});
		$row++;
	}
	return;
}

# +
# +  Write Content-Type Traffic Information 
# +
sub _traffic_type {
	my($self) = @_;

	my $ws  = $self->{WB}->add_worksheet( 'Content-Type Traffic' );
	my $row_st = 2;
	my $row    = 0;
	my $col_st = 0;

	$ws->merge_range(0,0,0,3,'',$fmt->{bold});
	$ws->write_string(0,0,"Traffic by identified Content-Type",$fmt->{bold});

	$ws->set_tab_color( 'silver' );

	# localize hash refs to allows key iteration
	my $TRAFFIC_TYPE = $self->{REPORT}{TRAFFIC}{TYPE};

	# Set column widths
	$ws->set_column(0,0,7);
	$ws->set_column(1,0,25);

	$ws->write_string(1,0,"Bytes",$fmt->{bold});
	$ws->write_string(1,1,"Content-Type",$fmt->{bold});	

	for my $type ( keys %$TRAFFIC_TYPE ) {
		# Filter out what looks like local addresses
		#next if $ip =~ /192\.168\./;
		my $bytes = $TRAFFIC_TYPE->{$type}{bytes} ||0;
		$ws->write_number($row_st+$row,$col_st,$bytes||'',$fmt->{normal});
		$ws->write_string($row_st+$row,$col_st+1,$type||'',$fmt->{normal});
		$row++;
	}
	return;
}

# +
# + DNS Worksheet
# +
sub _dns {
	my($self) = @_; 

	# define formatting
	my $dns_ws = $self->{WB}->add_worksheet( 'Hostnames & IPs' );
	$dns_ws->set_tab_color('blue');
	$dns_ws->merge_range(0,0,0,3,'',$fmt->{bold});
	$dns_ws->write_string(0,0,"Hostnames Detected",$fmt->{bold});

	# Set column widths
	$dns_ws->set_column(0,0,35);  # set witch to 40
	$dns_ws->set_column(1,1,15);  # set witch to 15
	$dns_ws->set_column(2,2,2);  # set witch to 15
	$dns_ws->set_column(3,3,25);  # set witch to 15
	$dns_ws->set_column(4,4,50);  # set witch to 15
	$dns_ws->set_column(5,5,50);  # set witch to 15
	$dns_ws->set_column(6,7,35);  # set witch to 15

	# Add headers
	$dns_ws->write_string(1,0,'Hostname',$fmt->{header});
	$dns_ws->write_string(1,1,'IP Address Use',$fmt->{header});

        $dns_ws->write_string(1,3,"Whois Domain",$fmt->{bold});
        $dns_ws->write_string(1,4,"Registrar",$fmt->{bold});
        $dns_ws->write_string(1,5,"Registrant",$fmt->{bold});
        $dns_ws->write_string(1,6,"Emails",$fmt->{bold});
        $dns_ws->write_string(1,7,"Name Servers",$fmt->{bold});

	# Add the Hostname Translation  cols A & B
	my $HOSTS   = $self->_consolidate_hosts();

	my $host_row = 2;
	foreach my $hostname (keys %$HOSTS) {
		$dns_ws->write_string( $host_row, 0, $hostname, $fmt->{normal} );
		$dns_ws->write_rich_string( $host_row, 1, $HOSTS->{$hostname}, $fmt->{wrap});

		# add Whois Info
		printf("Whois for: %s\n",$hostname);
		$self->{WHO}->go($hostname);

		$dns_ws->write_string( $host_row, 3, lc($self->{WHO}->whois_domain), $fmt->{normal} );
		$dns_ws->write_rich_string( $host_row, 4, $self->{WHO}->registrar||'', $fmt->{wrap} );
		$dns_ws->write_rich_string( $host_row, 5, $self->{WHO}->registrant||'', $fmt->{wrap} );
		$dns_ws->write_rich_string( $host_row, 6, $self->{WHO}->emails||'', $fmt->{wrap} );
		$dns_ws->write_rich_string( $host_row, 7, $self->{WHO}->nameservers||'', $fmt->{wrap} );
		
		$host_row++;
	}

	return;
}

# +
# +  Write Summary 
# +
sub _summary {
	my ($self) = @_;

	my $sum_ws  = $self->{WB}->add_worksheet( 'Summary' );

	$sum_ws->set_tab_color( 0x3 );	

	# Set column widths
	$sum_ws->set_column(0,0,9);
	$sum_ws->set_column(1,2,10);
	$sum_ws->set_column(3,3,2);
	$sum_ws->set_column(4,4,9);
	$sum_ws->set_column(5,6,10);

	# Add header
	$sum_ws->merge_range(0,0,0,14,'',$fmt->{bold});
	$sum_ws->write_string(0,0,"Summary - $orig_file",$fmt->{bold});

	# Add frames summary
	$sum_ws->merge_range(1,1,1,3,'',$fmt->{normal});
	$sum_ws->write_string(1,0,"Frames",$fmt->{bold});
	$sum_ws->write_string(1,1,$self->{REPORT}->{packets}||0,$fmt->{normal});

	$sum_ws->write_string(2,0,"Start time",$fmt->{bold});
	$sum_ws->merge_range(2,1,2,3,'',$fmt->{normal});
	$sum_ws->write_string(2,1,$self->{REPORT}->{start_time},$fmt->{normal});
	$sum_ws->write_string(3,0,"Stop time",$fmt->{bold});
	$sum_ws->merge_range(3,1,3,3,'',$fmt->{normal});
	$sum_ws->write_string(3,1,$self->{REPORT}->{stop_time},$fmt->{normal});

	return;
}

# +
# +  get hostname IP address(es)
# +
sub _get_ip_host {
        my($self,$ip) = @_;
        return $self->{REPORT}{DNS}{IP_to_HOST}{$ip} if $self->{REPORT}{DNS}{IP_to_HOST}{$ip};
        return $DNS->{IP_to_HOST}{$ip} if  $DNS->{IP_to_HOST}{$ip};
#        if(my $host = gethostbyaddr($ip,AF_INET)){
#		$DNS->{IP_to_HOST}{$ip}   ||= $host; 
#		$DNS->{HOST_to_IP}{$host} ||= $ip; 
#       }
        return $DNS->{IP_to_HOST}{$ip} || ' - lookup failed - ';
}

# +
# +  get hostname IP address(es)
# +
sub _get_host_ip {
        my($self,$host) = @_;
        return $self->{REPORT}{DNS}{HOST_to_IP}{$host} if $self->{REPORT}{DNS}{HOST_to_IP}{$host};
#        if(my $ip = inet_ntoa(inet_aton($host))){
#		$DNS->{IP_to_HOST}{$ip}   ||= $host; 
#		$DNS->{HOST_to_IP}{$host} ||= $ip; 
#	}
        return $DNS->{HOST_to_IP}{$host}; 
}

# +
# +  
# +
sub _consolidate_hosts {
	my ($self) = @_;
	my $IPS   = $self->{REPORT}{DNS}{IP_to_HOST};
	my $HOSTS = {};

	foreach my $ip (keys %$IPS) {
		my $hostname = $IPS->{$ip};
		$HOSTS->{$hostname} .= $ip."\n";
	}

	return $HOSTS;
}
	


# =============================
1;
