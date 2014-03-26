# =============================
  package Pcap::Xlsx::Reporter;
# =============================

use strict;
use Socket;
use Excel::Writer::XLSX;
use PCAP::GeoLocate;
use PCAP::Whois;
use File::Basename;
use Data::Dumper;
# - - - - - - - - - - - - - - - 
my $fmt    = {};
my $orig_file;

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  + 
# + + + + + + + + + + + + + + + + + + + +
sub new {
	my ($class,$file) = @_;

	my $outfile = sprintf('%s.v3.xlsx',$file);	
	my $WB = Excel::Writer::XLSX->new($outfile);

        $WB->set_properties(
                title    => sprintf('%s Network Analysis Report',$file),
                author   => 'David DeMartini  fbo  Appdetex.com',
                comments => 'Automated Network Traffic Analysis',
        );

	# set formatting
	_define_formatting($WB);

	my $self  = { 
		outfile    => $outfile,
		orig_file  => $file,
		basename   => _format_filename(basename($file)),
		WB         => $WB, 
		GEO        => new Pcap::GeoLocate,
		WHO        => new Pcap::Whois,
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

	# Process the report data
	$self->_process_conversations();

printf("CONVS %s\n",Dumper $self->{CONVS});

	# Write the report information
	$self->_summary();
	$self->_conversations_general();
	#$self->_media();
	$self->_add_dns();
	#$self->_traffic_ip();
	#$self->_traffic_host();
	#$self->_traffic_url();
	#$self->_traffic_type();
	#$self->_httpd();

	# Close and Save
	$self->{WB}->close();

	return $self->{outfile};
	
}

# +
# +  Write Summary 
# +
sub _summary {
	my ($self) = @_;

	my $sum_ws  = $self->{WB}->add_worksheet( 'Summary' );

	$sum_ws->set_tab_color( 'green' );	

	# Set column widths
	$sum_ws->set_column(4,4,3);
	$sum_ws->set_column(9,9,3);

	# Add header
	$sum_ws->merge_range(0,0,0,14,'',$fmt->{header});
	$sum_ws->write_string(0,0,sprintf('Network Analysis Summary for   [ %s ]',$self->{basename}),$fmt->{header});

	# Conversation Information
	$sum_ws->merge_range(2,0,2,14,'',$fmt->{section});
	$sum_ws->write_string(2,0,sprintf(' %d   Network Conversations with Remote Servers',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section});

	# Groupings
	$self->_insert_traffic_data_types(\$sum_ws,4,0,7);  # send worksheet, and starting co-ordinate and columns
	$self->_insert_traffic_data_destinations(\$sum_ws,4,5,8);  # send worksheet, and starting co-ordinate and columns
	$self->_insert_traffic_data_hostnames(\$sum_ws,4,10,14);  # send worksheet, and starting co-ordinate and columns

	return;

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
# +  Conversations
# + 
# + 	SAMPLE FIELDS
# + - - - - - - - - - - - - - - - - - - 
# +  'index' => 86,
# +  'host' => 'csi.gstatic.com',
# +  'Content-Type' => 'image/gif',
# +  'url' => 'http://csi.gstatic.com/csi?v=3&s=gmob&action=&rt=crf.39,cri.81',
# +  'dest_port' => 80,
# +  'bytes' => 2748,
# +  'dest_ip' => '188.40.69.72',
# +  'src_ip' => '192.168.2.6',
# +  'trans_data' => '',
# +  'proto' => 'tcp',
# +  'src_port' => 49848,
# +  'flags' => 2,
# +  'User-Agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Mobile/11B554a',
# +  'service' => 'World Wide Web HTTP',
# +  'uri' => '/csi?v=3&s=gmob&action=&rt=crf.39,cri.81',
# +  'Accept-Encoding' => 'gzip, deflate',
# +  'parts' => 6,
# +  'action' => 'GET'
# +  
sub _conversations_general {
	my ($self) = @_;

	my $ws  = $self->{WB}->add_worksheet( 'Conversations' );
	my @convs = @{$self->{CONVS}{ORDERED}};  # localize array, just because 
	my $current_row = 4;  # row to start inserting the conversation blocks

	$ws->set_tab_color( 'orange' );

        # Set column widths
       $ws->set_column(0,0,6);
       $ws->set_column(1,1,16);
       $ws->set_column(2,3,25);
       $ws->set_column(4,5,75);
       $ws->set_column(6,7,2);

	# Add header
	$ws->merge_range(0,0,0,7,'',$fmt->{header});
	$ws->write_string(0,0,sprintf('Network Conversations for   [ %s ]',$self->{basename}),$fmt->{header});

	# Conversation Information
	$ws->merge_range(2,0,2,7,'',$fmt->{section});
	$ws->write_string(2,0,sprintf(' %d  Network Conversations',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section});

	# Top Row Headings
	$ws->write_string(3,0,'Convrs.',$fmt->{title});
	$ws->write_string(3,1,'IP Address',$fmt->{title});
	$ws->write_string(3,2,'Hostname',$fmt->{title});
	$ws->write_string(3,3,'Content-Type',$fmt->{title});
	$ws->merge_range(3,4,3,5,'',$fmt->{title});
	$ws->write_string(3,4,'URL',$fmt->{title});

	# Start to loop through the items
	foreach my $conv (@convs){
		# process each element
		$current_row += $self->_add_conversation(\$ws,$current_row,$conv);  # add to worksheet and return how much space it used
	}

	return;
}

# +
# +  insert traffic types
# +
sub _insert_traffic_data_types {
	my($self,$ws,$row_start,$col_start,$col_end) = @_;

	my $PopTypes  = $self->{'CONVS'}{'POPULARITY'}{'traffic_types'};
	my $GrpTypes  = $self->{'CONVS'}{'GROUPED'}{'traffic_types'};
	
	my @types = ();
	my @destinations = ();
	my $total_types = scalar(@$PopTypes);
	my $top = ($total_types <= 10) ? $total_types : 10;
	my $title = sprintf('Top %d of %d Communication Methods',$top,$total_types);

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+3,$title,$fmt->{sub_sect});

	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Transfers',$fmt->{title});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+3,'',$fmt->{title});
	$$ws->write_string($row_start,$col_start+1,'Service Type',$fmt->{title});

	if(my @types = @$PopTypes){
		my $type_row_1 = $row_start + 1;
		for(my $i=0;$i<$top;$i++){
			my $type = shift(@types);
			$$ws->write_number($type_row_1,$col_start,$GrpTypes->{$type});
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+3,'',$fmt->{normal});
			$$ws->write_string($type_row_1,$col_start+1,$type);
			$type_row_1++;
		}
	}

	return;
}

# +
# +  insert traffic destinations 
# +
sub _insert_traffic_data_destinations {
	my($self,$ws,$row_start,$col_start,$col_end) = @_;

	my $PopDests  = $self->{'CONVS'}{'POPULARITY'}{'destinations'};
	my $GrpDests  = $self->{'CONVS'}{'GROUPED'}{'destinations'};
	
	my @ips = ();
	my @destinations = ();
	my $total_types = scalar(@$PopDests);
	my $top = ($total_types <= 10) ? $total_types : 10;
	my $title = sprintf('Top %d of %d Frequented IPs',$top,$total_types);

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+3,$title,$fmt->{sub_sect});
	
	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Transfers',$fmt->{title});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+3,'IP Address',$fmt->{title});

	if(my @ips = @$PopDests){
		my $type_row_1 = $row_start + 1;
		for(my $i=0;$i<$top;$i++){
			my $ip = shift(@ips);
			$$ws->write_number($type_row_1,$col_start,$GrpDests->{$ip});
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+3,'',$fmt->{normal});
			$$ws->write_string($type_row_1,$col_start+1,$ip);
			# add GeoLocation awesomeness
			$type_row_1++;
		}
	}

	return;
}

# +
# +  insert traffic destinations 
# +
sub _insert_traffic_data_hostnames {
	my($self,$ws,$row_start,$col_start,$col_end) = @_;

	my $PopHosts  = $self->{'CONVS'}{'POPULARITY'}{'hostnames'};
	my $GrpHosts  = $self->{'CONVS'}{'GROUPED'}{'hostnames'};
	
	my @ips = ();
	my @destinations = ();
	my $total_hosts = scalar(@$PopHosts);
	my $top = ($total_hosts <= 10) ? $total_hosts : 10;
	my $title = sprintf('Top %d of %d Frequented Hostnames',$top,$total_hosts);

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+4,$title,$fmt->{sub_sect});
	
	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Transfers',$fmt->{title});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+4,'Hostname',$fmt->{title});
#	$$ws->write_string($row_start,$col_start+1,'Hostname',$fmt->{title});

	if(my @hosts = @$PopHosts){
		my $type_row_1 = $row_start + 1;
		for(my $i=0;$i<$top;$i++){
			my $hostname = shift(@hosts);
			$$ws->write_number($type_row_1,$col_start,$GrpHosts->{$hostname});
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+4,$hostname,$fmt->{normal});
			# add more awesomenessd
			$type_row_1++;
		}
	}

	return;
}

# +
# +
# +  Create and add the Conversation Block
# +
sub _add_conversation($ws,$current_row,$conv) {
	my($self,$ws,$row,$conv) = @_;

	# RULE, no URL, no show
	return 0 unless $conv->{'url'};
#printf("\$ws = %s\n\$row=%s\n\$conv=%s\n",$ws,$row,$conv);

	my $ru = 0;  # rows used.

	#  Add first row
	$$ws->write_number($row+$ru,0,$conv->{'index'},$fmt->{conversation_index});
	$$ws->write_string($row+$ru,1,$conv->{'dest_ip'},$fmt->{conversation});
	$$ws->write_string($row+$ru,2,$conv->{'host'}||'',$fmt->{conversation});
	$$ws->write_string($row+$ru,3,$conv->{'Content-Type'}||'',$fmt->{conversation});
	$$ws->merge_range($row+$ru,4,$row+$ru,5,'',$fmt->{conversation});
	$$ws->write_string($row+$ru,4,$conv->{'url'},$fmt->{conversation});

	# Add Service Details
	my $domain = $conv->{host} || '';
	my $destip = sprintf('%s:%s',$conv->{dest_ip},$conv->{dest_port});
	my $domain_whois = sprintf("%s\nWhois stuff",$domain);
	my $ip_geoloc = sprintf("%s\nGeoLocation\n",$conv->{dest_ip});

	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Service',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'service'},$fmt->{normal});
	$$ws->write_string($row+$ru,4,$domain,$fmt->{normal});
	$$ws->write_string($row+$ru,5,$destip,$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Action',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'action'},$fmt->{normal});
#	$$ws->write_string($row+$ru,4,$domain_whois,$fmt->{normal});
#	$$ws->write_string($row+$ru,5,$ip_geoloc,$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Bytes',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_number($row+$ru,2,$conv->{'bytes'},$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Segments',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_number($row+$ru,2,$conv->{'parts'},$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Agent',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'User-Agent'},$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Encoding',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'Accept-Encoding'},$fmt->{normal});
	
	# Setup the cell merges
	$ru++;  #next row
	$$ws->merge_range($row+2,4,$row+$ru,4,$domain_whois,$fmt->{whois});  # Index Cell.
	$$ws->merge_range($row+2,5,$row+$ru,5,$ip_geoloc,$fmt->{whois});  # Index Cell.
	$$ws->merge_range($row,0,$row+$ru,0,$conv->{index},$fmt->{conversation_index});    # Index Cell.
	$$ws->merge_range($row+$ru,1,$row+$ru,3,'',$fmt->{normal});    # Index Cell.

	$ru++;  #last row
	$$ws->merge_range($row,6,$row+$ru-1,7,'',$fmt->{conversation_right_frame});    # Right Cell.
	$$ws->merge_range($row+$ru,0,$row+$ru,7,'',$fmt->{conversation_footer});    # Footer Cell.

	return $ru+1;
}

# +
# + DNS Worksheet
# +
sub _add_dns {
	my($self) = @_;

	# define formatting
	my $ws = $self->{WB}->add_worksheet( 'Hostnames & Whois' );
	$ws->set_tab_color('blue');

	# Add header
	my $title = sprintf('Hostnames Resolved by   [ %s ]',$self->{basename});
	$ws->merge_range(0,0,0,7,$title,$fmt->{header});

	# Set column widths
	$ws->set_column(0,0,35); 
	$ws->set_column(1,1,15); 
	$ws->set_column(2,2,2); 
	$ws->set_column(3,3,25); 
	$ws->set_column(4,4,50); 
	$ws->set_column(5,5,50); 
	$ws->set_column(6,7,35); 

	# Add headers
	$ws->write_string(2,0,'Hostname',$fmt->{title});
	$ws->write_string(2,1,'IP Addresses Used',$fmt->{title});
        $ws->write_string(2,2,'',$fmt->{title});
        $ws->write_string(2,3,'Whois Domain',$fmt->{title});
        $ws->write_string(2,4,'Registrar',$fmt->{title});
        $ws->write_string(2,5,'Registrant',$fmt->{title});
        $ws->write_string(2,6,'Emails',$fmt->{title});
        $ws->write_string(2,7,'Name Servers',$fmt->{title});

	# Add the Hostname Translation  cols A & B
	my $HOSTS   = $self->_consolidate_hosts();

	my $host_row = 3;
	foreach my $hostname (keys %$HOSTS) {
		$ws->write_string( $host_row, 0, $hostname, $fmt->{normal} );
		$ws->write_rich_string( $host_row, 1, join("\n",$HOSTS->{$hostname}), $fmt->{wrap});

		# add Whois Info
		printf("Whois for: %s\n",$hostname);
		$self->{WHO}->go($hostname);

		$ws->write_string( $host_row, 3, lc($self->{WHO}->whois_domain), $fmt->{normal} );
		$ws->write_rich_string( $host_row, 4, $self->{WHO}->registrar||'', $fmt->{wrap} );
		$ws->write_rich_string( $host_row, 5, $self->{WHO}->registrant||'', $fmt->{wrap} );
		$ws->write_rich_string( $host_row, 6, $self->{WHO}->emails||'', $fmt->{wrap} );
		$ws->write_rich_string( $host_row, 7, $self->{WHO}->nameservers||'', $fmt->{wrap} );
		
		$host_row++;
	}

	return;
}

# +
# +  Process the Conversations
# +
sub _process_conversations {
	my($self) = @_;

	my @conversations = ();
	my $conversation_ct = scalar(keys %{$self->{'REPORT'}});  # count of conversation records
	my $traffic_types   = {}; # hash of different traffic types
	my $destinations    = {}; # hash of different traffic destinations
	my $hostnames       = {}; # hash of different hostnames seen
	my $ip_to_host      = {}; # hash holds a lookup hash of IPs to hostnames
	my $host_to_ip      = {}; # hash hosts a lookup hash of hostnames to IPs

	foreach(my $ix=0;$ix < $conversation_ct;$ix++){
		my $rec  = $self->{'REPORT'}{$ix};
		my $ip   = $rec->{dest_ip}; # || _guess_ip($rec->{host});
		my $host = $rec->{host}; #    || _guess_host($ip);
		push(@conversations,$rec);  # put into the time sequence list
		$traffic_types->{$rec->{service}}++;
		$destinations->{$ip}++;
		$hostnames->{$host}++;
		$ip_to_host->{$ip}{$host}++ if ($host && $ip); # store all hostnames for a given IP or reversed.
		$host_to_ip->{$host}{$ip}++ if ($host && $ip); # store all ips for a given hostname
#printf("[%06d]  %s => %s  --  %s \n",$ix,$rec->{src_ip},$rec->{dest_ip},$rec->{service}||'');
	}

	return $self->{CONVS} = {  
		'COUNTS' => { 
			'conversations' => scalar(@conversations),
			'traffic_types' => scalar(keys %{$traffic_types}),
			'destinations'  => scalar(keys %{$destinations}),
		},
		'POPULARITY'   => {
			'traffic_types' => _popularity($traffic_types),
			'destinations'  => _popularity($destinations),
			'hostnames'     => _popularity($hostnames),
		},
		'GROUPED'  => {
			'traffic_types' => $traffic_types,
			'destinations'  => $destinations,
			'hostnames'     => $hostnames,
			'ip_to_host'    => $ip_to_host,
			'host_to_ip'    => $host_to_ip,
		},
		'ORDERED' => \@conversations,
	};
}

# +
# +
# +
sub _popularity {
	my($data) = @_;
	my @sorted;
	
	# perform the sort in scending order
	foreach my $proto (sort { $data->{$b} <=> $data->{$a} } keys %$data) {
		push @sorted,$proto;
	}
	return \@sorted; 
}

# +
# +  format the filename, hack of pcap parts
# +
sub _format_filename {
	my($filename) = @_;

	# remove pcap* suffix
	$filename =~ s/\.pcap[ng]{0,}$//g;  # remove suffix
	$filename =~ s/\s/_/g;

	return $filename;
}

# +
# +
# +
sub _consolidate_hosts {
	my ($self) = @_;
	my $HList = $self->{CONVS}{GROUPED}{host_to_ip};
	my $HOSTS = {};

	foreach my $host (keys %$HList) {
		$HOSTS->{$host} = join("\n",keys(%{$HList->{$host}}));
	}
	return $HOSTS;
}


# +
# +  Define formatting for the entire workbook
# + 
sub _define_formatting {
	my ($WB) = @_;
 
	# Define WorkBook formatting
	my $lt_grey = $WB->set_custom_color( 40, 236, 236, 236 );

	$fmt->{header} = $WB->add_format( bold => 1);
		$fmt->{header}->set_size( 20 );
		$fmt->{header}->set_color( 'white' );
		$fmt->{header}->set_bg_color( 'navy' );

	$fmt->{section} = $WB->add_format( bold => 1);
		$fmt->{section}->set_size( 16);
		$fmt->{section}->set_color( 'white' );
		$fmt->{section}->set_bg_color( 'blue' );
		
	$fmt->{sub_sect} = $WB->add_format( bold => 1);
		$fmt->{sub_sect}->set_size( 13 );
		$fmt->{sub_sect}->set_color( 'white' );
		$fmt->{sub_sect}->set_bg_color( 23 );

	$fmt->{conversation} = $WB->add_format( bold => 1);
		$fmt->{conversation}->set_size( 12 );
		$fmt->{conversation}->set_color( 'black' );
		$fmt->{conversation}->set_bg_color( $lt_grey );
		$fmt->{conversation}->set_top( 2 );
	$fmt->{conversation_index} = $WB->add_format( bold => 1, align => 'center', valign => 'top');
		$fmt->{conversation_index}->set_top( 2 );
		$fmt->{conversation_index}->set_left( 2 );
	$fmt->{conversation_footer} = $WB->add_format( bold => 1);
		$fmt->{conversation_footer}->set_top( 2 );
	$fmt->{conversation_right_frame} = $WB->add_format( bold => 1, align => 'right', valign => 'top');
		$fmt->{conversation_right_frame}->set_top( 2 );
		$fmt->{conversation_right_frame}->set_right( 2 );

	$fmt->{title_lt} = $WB->add_format( bold => 0);
		$fmt->{title_lt}->set_color( 'gray' );

	$fmt->{whois} = $WB->add_format( bold => 0, align => 'left', valign => 'top');
		$fmt->{whois}->set_text_wrap();

	$fmt->{title}  = $WB->add_format( bold => 1);

	$fmt->{bold}   = $WB->add_format( bold => 1);

	$fmt->{normal} = $WB->add_format( bold => 0, align => 'left', valign => 'top');

	$fmt->{wrap}   = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
	$fmt->{wrap_c} = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
		$fmt->{wrap_c}->set_align('vjustify');
	
	return;
}

# =============================
1;
