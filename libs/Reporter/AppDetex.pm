# =============================
  package Reporter::Interrogator::AppDetex;
# =============================

use strict;
use Socket;
use Excel::Writer::XLSX;
use PCAP::GeoLocate;
use PCAP::Whois;
use PCAP::ContentType;
use File::Basename;
use Text::Wrap;
use Image::Size;
use Reporter::FormatsAppDetex;
use Data::Dumper;
# - - - - - - - - - - - - - - - 
my $fmt    = {};
my $orig_file;

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  + 
# + + + + + + + + + + + + + + + + + + + +
sub new {
	my $class = shift;
	my $self  = shift;
	$self->{outfile}  = sprintf('%s.appdetex.xlsx',$self->{orig_file});	
	$self->{basename} = _format_filename(basename($self->{orig_file})); 
	$self->{GEO}      = new Pcap::GeoLocate;
	$self->{WHO}      = new Pcap::Whois;

	$self->{WB} = Excel::Writer::XLSX->new($self->{outfile});

        $self->{WB}->set_properties(
                title     => sprintf('%s Network Analysis Report ',$self->{title}),
		comments  => $self->{desc},
                author    => 'David DeMartini  fbo  Appdetex.com',
                comments  => 'Automated Network Traffic Analysis',
        );

	# set formatting
	$fmt = Reporter::Formats::set_formatting($self->{WB});

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

#printf("CONVS %s\n",Dumper $self->{CONVS});

	# Write the report information
	$self->_summary();

	$self->_network_analysis();

	$self->_conversations_media();

	$self->_conversations_payload();

	$self->_conversations_general();

	$self->_add_dns();

#	$self->_add_ipgeo();
#	#$self->_traffic_host();
#	#$self->_traffic_url();
#	#$self->_traffic_type();

	# Close and Save
	$self->{WB}->close();

	return $self->{outfile};
	
}

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Write Summary 
# +
sub _summary {
	my ($self) = @_;

	my $sum_ws  = $self->{WB}->add_worksheet( 'Summary' );

	my $block_start = 0;
	my $block_end   = 0;
	my $next_block_start = 0;
	my $temp;
	my $x_factor    = 0.3;
	my $target_px   = 115;   #target pixel width

	$sum_ws->set_tab_color( 'green' );	

	# Set column widths
	$sum_ws->set_column(4,4,3);
	$sum_ws->set_column(9,9,3);

	# Add banner
	$sum_ws->set_row(0,32);
	
	$sum_ws->merge_range($block_start,0,$block_start,14,'',$fmt->{banner});
	$sum_ws->write_string($block_start,0,'AppDetex App Interrogation Report',$fmt->{banner});

	# Content for Investigation 
	$block_start += 2;
	$sum_ws->set_row($block_start,26);
	$sum_ws->merge_range($block_start,0,$block_start,3,'Content for Investigation',$fmt->{info_head_dk});
	$sum_ws->merge_range($block_start,4,$block_start,14,$self->{title},$fmt->{info_head_lt});

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'App Title ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,$self->{title},$fmt->{info_app_title});
		
	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Publisher ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,$self->{publisher},$fmt->{info_large});

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Description ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start+1,14,$self->{desc},$fmt->{info_desc});

	# image add and manipulation
	my ($img_x,$img_y) = imgsize($self->{logo});
	$x_factor = ($target_px / ($img_x+1));  # why the +1 ? simply to prevent a division by 0 error
	$sum_ws->set_row(++$block_start,95);  # set the cell height to some semi-reasonable amount.
	$sum_ws->merge_range($block_start,0,$block_start,1,'',$fmt->{info_label});
	$sum_ws->insert_image($block_start,0,$self->{logo},5,5,$x_factor,$x_factor);

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Store ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,$self->{store},$fmt->{info_large});

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Price ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,$self->{price},$fmt->{info_large});

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Category ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,ucfirst($self->{category}),$fmt->{info_large});

	$sum_ws->merge_range(++$block_start,0,$block_start,1,'Aprox Downloads ',$fmt->{info_label});
	$sum_ws->merge_range($block_start,2,$block_start,14,$self->{downloads},$fmt->{info_large});

	return;
}

# ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +
# +  Network Analysis 
# +
sub _network_analysis {
	my ($self) = @_;

	my $neta_ws  = $self->{WB}->add_worksheet( 'Network Analysis' );

	my $block_start = 0;
	my $block_end   = 0;
	my $next_block_start = 0;
	my $temp;

	$neta_ws->set_tab_color( 'red' );	

	# Set column widths
	$neta_ws->set_column(4,4,3);
	$neta_ws->set_column(9,9,3);

	# Add banner
	$neta_ws->set_row(0,32);
	$neta_ws->merge_range($block_start,0,$block_start,14,'',$fmt->{banner});
	$neta_ws->write_string($block_start,0,sprintf('Network Analysis Summary for     %s',$self->{title}),$fmt->{banner});

	# Conversation Information
	$block_start += 2;
	$neta_ws->merge_range($block_start,0,$block_start,14,'',$fmt->{section_head});
	$neta_ws->write_string($block_start,0,sprintf(' %d  Network Conversations with Remote Servers',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section_head});

	# Groupings
	$next_block_start = $block_start + 2;
	if($temp = $self->_insert_traffic_data_types(\$neta_ws,$next_block_start,0,4)) {  # send worksheet, and starting co-ordinate and columns
		$block_start = ($temp > $block_start) ? $temp : $block_start;
	}
	if($temp = $self->_insert_traffic_data_destinations(\$neta_ws,$next_block_start,5,8)) {  # send worksheet, and starting co-ordinate and columns
		$block_start = ($temp > $block_start) ? $temp : $block_start;
	}
	if($temp = $self->_insert_traffic_data_hostnames(\$neta_ws,$next_block_start,10,14)) {  # send worksheet, and starting co-ordinate and columns
		$block_start = ($temp > $block_start) ? $temp : $block_start;
	}

	# Next block of items
	$next_block_start = $block_start + 2;  # leave some space before next block

	if($temp = $self->_insert_traffic_data_media(\$neta_ws,$next_block_start,0,4)) {  # send worksheet, and starting co-ordinate and columns
		$block_start = ($temp > $block_start) ? $temp : $block_start;
	}

	# Next block of items
	$next_block_start = $block_start + 2;  # leave some space before next block

	return;

#	# Add frames summary
#	$sum_ws->merge_range(1,1,1,3,'',$fmt->{normal});
#	$sum_ws->write_string(1,0,"Frames",$fmt->{bold});
#	$sum_ws->write_string(1,1,$self->{REPORT}->{packets}||0,$fmt->{normal});
#
#	$sum_ws->write_string(2,0,"Start time",$fmt->{bold});
#	$sum_ws->merge_range(2,1,2,3,'',$fmt->{normal});
#	$sum_ws->write_string(2,1,$self->{REPORT}->{start_time}||'',$fmt->{normal});
#	$sum_ws->write_string(3,0,"Stop time",$fmt->{bold});
#	$sum_ws->merge_range(3,1,3,3,'',$fmt->{normal});
#	$sum_ws->write_string(3,1,$self->{REPORT}->{stop_time}||'',$fmt->{normal});

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
	$ws->merge_range(0,0,0,7,'',$fmt->{banner});
	$ws->write_string(0,0,sprintf('Network Conversations for     %s',$self->{title}),$fmt->{banner});

	# Conversation Information
	$ws->merge_range(2,0,2,7,'',$fmt->{section_head});
	$ws->write_string(2,0,sprintf(' %d  Network Conversations',$self->{CONVS}{COUNTS}{conversations}),$fmt->{section_head});

	# Top Row Headings
	$ws->write_string(3,0,'Convrs.',$fmt->{col_head});
	$ws->write_string(3,1,'IP Address',$fmt->{col_head});
	$ws->write_string(3,2,'Hostname',$fmt->{col_head});
	$ws->write_string(3,3,'Content-Type',$fmt->{col_head});
	$ws->merge_range(3,4,3,5,'',$fmt->{col_head});
	$ws->write_string(3,4,'URL',$fmt->{col_head});

	# Start to loop through the items
	foreach my $conv (@convs){
		# process each element
		$current_row += $self->_add_conversation(\$ws,$current_row,$conv);  # add to worksheet and return how much space it used
	}

	return;
}

# +
# +   Traffic with a content type the indicates it's likely to be media
# +
sub _conversations_media {
	my ($self) = @_;
	my @convs = @{$self->{CONVS}{MEDIA}};  # localize array, just because 
	return unless scalar(@convs);

	my $ws  = $self->{WB}->add_worksheet( 'Media' );
	my $current_row = 4;  # row to start inserting the conversation blocks

	$ws->set_tab_color( 'red' );

        # Set column widths
	$ws->set_column(0,0,6);
	$ws->set_column(1,1,16);
	$ws->set_column(2,3,25);
	$ws->set_column(4,5,75);
	$ws->set_column(6,7,2);

	# Add header
	$ws->merge_range(0,0,0,7,'',$fmt->{banner});
	$ws->write_string(0,0,sprintf('Audio / Video Conversations for     %s' ,$self->{title}),$fmt->{banner});

	# Conversation Information
	$ws->merge_range(2,0,2,7,'',$fmt->{section_head});
	$ws->write_string(2,0,sprintf(' %d  Network Conversations',scalar(@convs)),$fmt->{section_head});

	# Top Row Headings
	$ws->write_string(3,0,'Convrs.',$fmt->{col_head});
	$ws->write_string(3,1,'IP Address',$fmt->{col_head});
	$ws->write_string(3,2,'Hostname',$fmt->{col_head});
	$ws->write_string(3,3,'Content-Type',$fmt->{col_head});
	$ws->merge_range(3,4,3,5,'',$fmt->{col_head});
	$ws->write_string(3,4,'URL',$fmt->{col_head});

	# Start to loop through the items
	foreach my $conv (@convs){
		# process each element
		$current_row += $self->_add_conversation(\$ws,$current_row,$conv);  # add to worksheet and return how much space it used
	}

	return;
}

# +
# +   Traffic with a content type the indicates it's likely to be media
# +
sub _conversations_payload {
	my ($self) = @_;
	my @convs = @{$self->{CONVS}{PAYLOAD}};  # localize array, just because 
	return unless scalar(@convs);

	my $ws  = $self->{WB}->add_worksheet( 'Payloads' );
	my $current_row = 4;  # row to start inserting the conversation blocks

	$ws->set_tab_color( 'red' );

        # Set column widths
	$ws->set_column(0,0,6);
	$ws->set_column(1,1,16);
	$ws->set_column(2,3,25);
	$ws->set_column(4,5,75);
	$ws->set_column(6,7,2);

	# Add header
	$ws->merge_range(0,0,0,7,'',$fmt->{banner});
	$ws->write_string(0,0,sprintf('Payload Typical Conversations for     %s',$self->{title}),$fmt->{banner});

	# Conversation Information
	$ws->merge_range(2,0,2,7,'',$fmt->{section_head});
	#$ws->write_string(2,0,sprintf(' %d  Network Conversations',scalar(@convs)),$fmt->{section_head});
	$ws->write_string(2,0,'Discovered Payloads',$fmt->{section_head});

	# Top Row Headings
	$ws->write_string(3,0,'Convrs.',$fmt->{col_head});
	$ws->write_string(3,1,'IP Address',$fmt->{col_head});
	$ws->write_string(3,2,'Hostname',$fmt->{col_head});
	$ws->write_string(3,3,'Content-Type',$fmt->{col_head});
	$ws->merge_range(3,4,3,5,'',$fmt->{col_head});
	$ws->write_string(3,4,'URL',$fmt->{col_head});

	# Start to loop through the items
	foreach my $conv (@convs){
		# process each element
		$current_row += $self->_add_conversation_payload(\$ws,$current_row,$conv);  # add to worksheet and return how much space it used
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

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+3,$title,$fmt->{group_head});
	$row_start++;

	# add the titles
	$$ws->write_string($row_start,$col_start,'Transfers',$fmt->{col_head});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+3,'Service Type',$fmt->{col_head});

	my $type_row_1 = $row_start + 1;

	if(my @types = @$PopTypes){
		for(my $i=0;$i<$top;$i++){
			my $type = shift(@types);
			$$ws->write_number($type_row_1,$col_start,$GrpTypes->{$type}||'');
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+3,$type,$fmt->{normal});
			$type_row_1++;
		}
	}

	return $type_row_1;
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

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+3,$title,$fmt->{group_head});
	
	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Transfers',$fmt->{col_head});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+3,'IP Address',$fmt->{col_head});

	my $type_row_1 = $row_start + 1;

	if(my @ips = @$PopDests){
		for(my $i=0;$i<$top;$i++){
			my $ip = shift(@ips);
			$$ws->write_number($type_row_1,$col_start,$GrpDests->{$ip}||'');
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+3,$ip||'',$fmt->{normal});
			# add GeoLocation awesomeness
				$self->{GEO}->go($ip);
				my $GeoInfo = $self->{GEO}->get_geoblock();
			$type_row_1++;
		}
	}

	return $type_row_1;
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
	my $type_row_1 = $row_start + 1;

	$$ws->merge_range($row_start,$col_start,$row_start,$col_start+4,$title,$fmt->{group_head});
	
	# add the titles
	$$ws->write_string(++$row_start,$col_start,'Transfers',$fmt->{col_head});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+4,'Hostname',$fmt->{col_head});
#	$$ws->write_string($row_start,$col_start+1,'Hostname',$fmt->{col_head});

	my $type_row_1 = $row_start + 1;

	if(my @hosts = @$PopHosts){
		for(my $i=0;$i<$top;$i++){
			my $hostname = shift(@hosts);
			$$ws->write_number($type_row_1,$col_start,$GrpHosts->{$hostname}||0);
			$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+4,$hostname||'',$fmt->{normal});
			# add more awesomenessd
			$type_row_1++;
		}
	}

	return;
}

# +
# +  insert traffic types
# +
sub _insert_traffic_data_media {
	my($self,$ws,$row_start,$col_start,$col_end) = @_;

	return 0 unless scalar(@{$self->{'CONVS'}{'MEDIA'}});

	my $file_sizes = {};  # store file -> bytes mapping

	foreach my $rec (@{$self->{'CONVS'}{'MEDIA'}}) {
		if(my($path,$junk) = split '\?',$rec->{url},2){
			$file_sizes->{basename($path)}{bytes} += $rec->{bytes};
			$file_sizes->{basename($path)}{host} = $rec->{host};
		}
	}

	return 0 unless scalar(keys %$file_sizes);

	my $title = sprintf('%d Media File Types Discovered',scalar(keys %$file_sizes));

	$$ws->merge_range($row_start,$col_start,$row_start,14,$title,$fmt->{section_head});
	$row_start += 2; #shimit
	
	$$ws->merge_range($row_start,$col_start,$row_start,6,'Media Type Transfers',$fmt->{group_head});
	$row_start++; #shimit

	# add the titles
	$$ws->write_string($row_start,$col_start,'Bytes',$fmt->{col_head});
	$$ws->merge_range($row_start,$col_start+1,$row_start,$col_start+2,'Related Host',$fmt->{col_head});
	$$ws->merge_range($row_start,$col_start+3,$row_start,$col_start+6,'Filename',$fmt->{col_head});

	my $type_row_1 = $row_start + 1;

	foreach my $filename (keys %$file_sizes){	
		$$ws->write_number($type_row_1,$col_start,$file_sizes->{$filename}{bytes}||0,$fmt->{normal});
		$$ws->merge_range($type_row_1,$col_start+1,$type_row_1,$col_start+2,$file_sizes->{$filename}{host}||'',$fmt->{normal});
		$$ws->merge_range($type_row_1,$col_start+3,$type_row_1,$col_start+6,$filename||'',$fmt->{normal});
		$type_row_1++;
	}

	return $type_row_1;
}

# +
# +  Create and add the Conversation Block
# +
sub _add_conversation($ws,$current_row,$conv) {
	my($self,$ws,$row,$conv) = @_;

	# RULE, no URL, no show
	return 0 unless $conv->{'url'};

	my $ru = 0;  # rows used.

	#  Add first row
	$$ws->write_number($row+$ru,0,$conv->{'index'}||0,$fmt->{conversation_index});
	$$ws->write_string($row+$ru,1,$conv->{'dest_ip'}||'',$fmt->{conversation});
	$$ws->write_string($row+$ru,2,$conv->{'host'}||'',$fmt->{conversation});
	$$ws->write_string($row+$ru,3,$conv->{'Content-Type'}||'',$fmt->{conversation});
	$$ws->merge_range($row+$ru,4,$row+$ru,5,'',$fmt->{conversation});
	$$ws->write_string($row+$ru,4,$conv->{'url'}||'',$fmt->{conversation});

	# Add Service Details;
	$self->{WHO}->go($conv->{host});
	$self->{GEO}->go($conv->{dest_ip});
	my $domain       = $self->{WHO}->whois_domain() || $conv->{host}; 
	my $destip       = sprintf('%s:%s',$conv->{dest_ip},$conv->{dest_port});
	my $domain_whois = $self->{WHO}->registrar();
	my $ip_geoloc    = $self->{GEO}->get_geoblock(); 

	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Service',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,$conv->{'service'}||'',$fmt->{normal});
	$$ws->write_string($row+$ru,4,lc($domain)||'',$fmt->{title_lt});
	$$ws->write_string($row+$ru,5,lc($destip)||'',$fmt->{title_lt});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Action',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,$conv->{'action'}||'',$fmt->{normal});
#	$$ws->write_string($row+$ru,4,$domain_whois||'',$fmt->{normal});
#	$$ws->write_string($row+$ru,5,$ip_geoloc||'',$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Bytes',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_number($row+$ru,2,$conv->{'bytes'}||0,$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Segments',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_number($row+$ru,2,$conv->{'parts'}||0,$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Agent',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,$conv->{'User-Agent'}||'',$fmt->{normal});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Encoding',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,$conv->{'Accept-Encoding'}||'',$fmt->{normal});
	
	# Setup the cell merges
	$ru++;  #next row
	$$ws->merge_range($row+2,4,$row+$ru,4,$domain_whois||'',$fmt->{whois});  # Index Cell.
	$$ws->merge_range($row+2,5,$row+$ru,5,$ip_geoloc||'',$fmt->{whois});  # Index Cell.
	$$ws->merge_range($row,0,$row+$ru,0,$conv->{index}||0,$fmt->{conversation_index});    # Index Cell.
	$$ws->merge_range($row+$ru,1,$row+$ru,3,'',$fmt->{normal});    # Index Cell.

	$ru++;  #last row
	$$ws->merge_range($row,6,$row+$ru-1,7,'',$fmt->{conversation_right_frame});    # Right Cell.
	$$ws->merge_range($row+$ru,0,$row+$ru,7,'',$fmt->{conversation_footer});    # Footer Cell.

	return $ru+1;
}

# +
# +
# +  Create and add the Conversation Payload Special 
# +
sub _add_conversation_payload($ws,$current_row,$conv) {
	my($self,$ws,$row,$conv) = @_;

	# RULE, no URL, no show
	return 0 unless $conv->{'url'};
	return 0 unless $conv->{'data'};

	my $ru = 0;  # rows used.

	#  Add first row
	$$ws->write_number($row+$ru,0,$conv->{'index'},$fmt->{conversation_index});
	$$ws->write_string($row+$ru,1,$conv->{'dest_ip'},$fmt->{conversation});
	$$ws->write_string($row+$ru,2,$conv->{'host'}||'',$fmt->{conversation});
	$$ws->write_string($row+$ru,3,$conv->{'Content-Type'}||'',$fmt->{conversation});
	$$ws->merge_range($row+$ru,4,$row+$ru,5,'',$fmt->{conversation});
	$$ws->write_string($row+$ru,4,$conv->{'url'},$fmt->{conversation});

	# Add Service Details
	my $domain  = $conv->{host} || '';
	my $destip  = sprintf('%s:%s',$conv->{dest_ip},$conv->{dest_port});
	my $payload = $conv->{data} || '-- no payload extracted --';
	my $decoded = $conv->{decoded_data} || '-- no payload decoded --';

	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Service',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'service'},$fmt->{normal});
	$$ws->write_string($row+$ru,4,'Raw Payload',$fmt->{title_lt});
	$$ws->write_string($row+$ru,5,'Decoded Payload',$fmt->{title_lt});
	$ru++;  #next row
	$$ws->write_string($row+$ru,1,'Action',$fmt->{title_lt});
	$$ws->merge_range($row+$ru,2,$row+$ru,3,'',$fmt->{normal});
	$$ws->write_string($row+$ru,2,$conv->{'action'},$fmt->{normal});
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
	$$ws->merge_range($row+2,4,$row+$ru,4,$payload,$fmt->{whois});  # Payload Cell.
	$$ws->merge_range($row+2,5,$row+$ru,5,$decoded,$fmt->{whois});  # Payload Cell.
	$$ws->merge_range($row,0,$row+$ru,0,$conv->{index},$fmt->{conversation_index});    # Index Cell.
	$$ws->merge_range($row+$ru,1,$row+$ru,3,'',$fmt->{normal});    # ??? Cell.

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
	my $title = sprintf('Hostnames Resolved by  %s',$self->{banner});
	$ws->merge_range(0,0,0,7,$title,$fmt->{banner});

	# Set column widths
	$ws->set_column(0,0,35); 
	$ws->set_column(1,1,15); 
	$ws->set_column(2,2,2); 
	$ws->set_column(3,3,25); 
	$ws->set_column(4,4,50); 
	$ws->set_column(5,5,50); 
	$ws->set_column(6,7,35); 

	# Add headers
	# - pretty
	$ws->merge_range(2,0,2,1,'Hostname Info',$fmt->{section_head});  
	$ws->merge_range(2,3,2,8,'Whois Info',$fmt->{section_head}); 

	# - column
	$ws->write_string(3,0,'Hostname',$fmt->{col_head});
	$ws->write_string(3,1,'IP Addresses Used',$fmt->{col_head});
        $ws->write_string(3,2,'',$fmt->{col_head});
        $ws->write_string(3,3,'Whois Domain',$fmt->{col_head});
        $ws->write_string(3,4,'Registrar',$fmt->{col_head});
        $ws->write_string(3,5,'Registrant',$fmt->{col_head});
        $ws->write_string(3,6,'Emails',$fmt->{col_head});
        $ws->write_string(3,7,'Name Servers',$fmt->{col_head});

	# Add the Hostname Translation  cols A & B
	my $HOSTS   = $self->_consolidate_hosts();

	my $host_row = 4;
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
# + IP Geo Info 
# +
sub _add_ipgeo {
	my($self) = @_;

	# define formatting
	my $ws = $self->{WB}->add_worksheet( 'IP Geographic Location' );
	$ws->set_tab_color('blue');

	# Add header
	my $title = sprintf('IPs Related to  %s',$self->{banner});
	$ws->merge_range(0,0,0,7,$title,$fmt->{banner});

	return;
}

# +
# +  Process the Conversations
# +
sub _process_conversations {
	my($self) = @_;

	# + -- lists
	my @conversations   = ();
	my @media           = ();
	my @payloads        = ();
	# + -- hashes 
	my $traffic_types   = {}; # hash of different traffic types
	my $destinations    = {}; # hash of different traffic destinations
	my $hostnames       = {}; # hash of different hostnames seen
	my $ip_to_host      = {}; # hash holds a lookup hash of IPs to hostnames
	my $host_to_ip      = {}; # hash hosts a lookup hash of hostnames to IPs
	# + -- scalars
	my $conversation_ct = scalar(keys %{$self->{'REPORT'}});  # count of conversation records

	foreach(my $ix=0;$ix < $conversation_ct;$ix++){
		my $rec   = $self->{'REPORT'}{$ix};
		my $ip    = $rec->{dest_ip}; # || _guess_ip($rec->{host});
		my $host  = $rec->{host}; #    || _guess_host($ip);
		push(@conversations,$rec);  # put into the time sequence list
		push(@media,$rec) if Pcap::ContentType::is_media($rec->{'Content-Type'}||'');
		push(@payloads,$rec) if Pcap::ContentType::is_payload($rec->{'Content-Type'}||'');
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
		'ORDERED'   => \@conversations,
		'MEDIA'     => \@media,
		'PAYLOAD'   => \@payloads,
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
# +  --  defines a CRUDE text wrapping strategy
# +
sub _make_wrappy {
	my($str) = @_;

	# do some text wrapping automagically
	$Text::Wrap::columns = 132;

	return wrap('','',$str);
}

# =============================
1;
