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
		basename   => basename($file),
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
	#$self->_dns();
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
#	$sum_ws->set_column(0,0,9);
#	$sum_ws->set_column(1,2,10);
#	$sum_ws->set_column(3,3,2);
#	$sum_ws->set_column(4,4,9);
#	$sum_ws->set_column(5,6,10);

	# Add header
	$sum_ws->merge_range(0,0,0,14,'',$fmt->{header});
	$sum_ws->write_string(0,0,sprintf('Network Analysis Summary for   [ %s ]',$self->{basename}),$fmt->{header});

	# Conversation Information
	$sum_ws->merge_range(2,0,2,14,'',$fmt->{section});
	$sum_ws->write_string(2,0,sprintf(' %d   Network Conversations with Remote Servers',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section});

	# Groupings
	$self->_insert_traffic_data_types(\$sum_ws,4,0,7);  # send worksheet, and starting co-ordinate and columns
	$self->_insert_traffic_data_destinations(\$sum_ws,4,6,10);  # send worksheet, and starting co-ordinate and columns

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

	$ws->set_tab_color( 'orange' );

	# Add header
	$ws->merge_range(0,0,0,14,'',$fmt->{header});
	$ws->write_string(0,0,sprintf('Network Conversations for   [ %s ]',$self->{basename}),$fmt->{header});

	# Conversation Information
	$ws->merge_range(2,0,2,14,'',$fmt->{section});
	$ws->write_string(2,0,sprintf(' %d  Network Conversations',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section});

	# Add Row Headings
	$ws->write_number(3,0,'Index',$fmt->{title});
	$ws->write_string(3,1,'Hostname',$fmt->{title});
	$ws->write_string(3,2,'IP Address',$fmt->{title});
	$ws->write_number(3,3,'Port',$fmt->{title});
	$ws->write_string(3,4,'Service',$fmt->{title});
	$ws->write_string(3,5,'Content Type',$fmt->{title});
	$ws->write_string(3,0,$item,$fmt->{title});
	$ws->write_string(3,0,$item,$fmt->{title});
	$ws->write_string(3,0,$item,$fmt->{title});
	$ws->write_string(3,0,$item,$fmt->{title});

	# Start to loop through the items
	foreach $conv (@$self->{CONVS}{ORDERED}){
		# process each element


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

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+4,'',$fmt->{sub_sect});
	$$ws->write_string($row_start,$col_start,$title,$fmt->{sub_sect});

	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Events',$fmt->{title});
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
	my $title = sprintf('Top %d of %d Frequent IPs Contacted',$top,$total_types);

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+4,'',$fmt->{sub_sect});
	$$ws->write_string($row_start,$col_start,$title,$fmt->{sub_sect});
	
	# add the titles
	$$ws->write_string(++$row_start,$col_start,'IP Events',$fmt->{title});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+2,'',$fmt->{title});
	$$ws->write_string($row_start,$col_start+1,'Remote IP Address',$fmt->{title});

	if(my @ips = @$PopDests){
		my $type_row_1 = $row_start + 1;
		for(my $i=0;$i<$top;$i++){
			my $ip = shift(@ips);
			$$ws->write_number($type_row_1,$col_start,$GrpDests->{$ip});
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+2,'',$fmt->{normal});
			$$ws->write_string($type_row_1,$col_start+1,$ip);
			# add GeoLocation awesomeness
			$type_row_1++;
		}
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

	foreach(my $ix=0;$ix < $conversation_ct;$ix++){
		my $rec = $self->{'REPORT'}{$ix};
		push(@conversations,$rec);  # put into the time sequence list
		$traffic_types->{$rec->{service}}++;
		$destinations->{$rec->{dest_ip}}++;
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
		},
		'GROUPED'  => {
			'traffic_types' => $traffic_types,
			'destinations'  => $destinations,

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
# +  Define formatting for the entire workbook
# + 
sub _define_formatting {
	my ($WB) = @_;
 
	# Define WorkBook formatting

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
#		$fmt->{sub_sect}->set_color( 'black' );
#		$fmt->{sub_sect}->set_bg_color( 23 );
		
	$fmt->{title}  = $WB->add_format( bold => 1);

	$fmt->{bold}   = $WB->add_format( bold => 1);

	$fmt->{normal} = $WB->add_format( bold => 0, align => 'left', valign => 'top');

	$fmt->{wrap}   = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
	
	return;
}

# =============================
1;
