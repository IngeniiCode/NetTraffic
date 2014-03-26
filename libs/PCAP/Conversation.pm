# =============================
  package Pcap::Conversation;
# =============================
use strict;

# =============================
#  Define required modules
# =============================
use Net::Pcap;
use Net::DNS::Packet;
use NetPacket::Ethernet qw(:ALL);
use NetPacket::IP qw(:ALL);
use NetPacket::TCP qw(:ALL);
use NetPacket::UDP qw(:ALL);
use Pcap::PortService; 
use Pcap::ContentType;
# - - - used for encoding issues - - -
use utf8;
use Text::Unidecode;
# - - - implimen a SWITCH for PERL - - -
use Switch;
# - - - - - - - - - - - - - - 
use Data::Dumper;  # for debugging

# =============================
#  Define  Package Variables
# =============================
my $PORTS = Pcap::PortService->new();  # init ports service

# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  +
# + + + + + + + + + + + + + + + + + + + +
sub new {
        my ($class,$args) = @_;  # ingest package name, and any args
        my $self  = { 
		filter_str => $args->{filter} || 'tcp',  # set the default filter value	
		conv_index => 0,  #  protocol conversations index
	};
	return bless ($self, $class); # this is what makes a reference into an object
}

# +
# +  set the fitler object will use to decode pcap
# +
sub set_filter {
	my($self,$filter_str) = @_;

	return $self->{filter_str} = $filter_str;
}


# +
# + Open connections to pcap file and start iterating on sections
# +
# +    UDP traffic is checked first to create the internal DNS
# +    cache.
# +
# +    TCP traffic looking for all the other exiting bits of 
# +    information, datagrams, telegrams, miligrams and gram crackers
# +
sub process_file {
	my($self,$infile) = @_;

	# Wipe clean the oject's cache
	$self->{C} = undef;  # totaly destroy the cache.

	# Set infile 
	$self->{infile} = $infile;
	printf("Use pcap file %s\n",$self->{infile});

	# Collect Conversations
	$self->_loop('syn_only');

	# Process each Conversation
	$self->_process_conversations();

#	# COLLECT THE TCP PACKETS
#	$self->_loop('tcp');
#
#	# COLLECT THE UDP PACKETS
#	$self->_loop('udp');

	return $self->{CONV};
}

# +
# +   Conversation Processing
# +
sub _process_conversations {
	my($self) = @_;

	foreach my $cIndex (keys %{$self->{'CONV'}}){
		my $filter;
		my $filter_c;  # hold the compiled filter
		my $C = $self->{'CONV'}{$cIndex};  # localize this thing
		# Build a filter based on this conversations knows
		# read entire conversation
		# construct a filter
		$filter = sprintf('(host %s and host %s) and (port %d and port %d)',$C->{src_ip},$C->{dest_ip},$C->{src_port},$C->{dest_port});
#printf("====== FILTER: %s ========\n",$filter);
		$self->_assemble_conversation($cIndex,$filter);
	
	}
	return;
}

# +
# +   Packet Processing
# +
sub _loop {
	my($self,$proto) = @_;
	# -- beware of locals
	my $filter_c;  # holder for compiled filter
	my $fname = sprintf('_proc_%s',$proto||'tcp');

       	# init the pcap file for processing. 
        $self->_init_pcap();  # not required to set if already set

	# -- reset conversation counter
	$self->{conversation_index} = 0;

	if($proto ne 'syn_only') {	
		# create the filter
		Net::Pcap::compile( $self->{PCAP}, \$filter_c, $proto, 1, undef );
		Net::Pcap::setfilter( $self->{PCAP}, $filter_c );
	}

	# read all the packets
	Net::Pcap::loop( $self->{PCAP}, -1, \&$fname, $self );  # self is passed as user data

	# close the network file (since we have finished our processing)
	Net::Pcap::close( $self->{PCAP} );

	return;
}
	
# +
# +   Packet Processing
# +
sub _assemble_conversation {
	my($self,$cIndex,$filter) = @_;
	# -- beware of locals
	my $filter_c;  # holder for compiled filter

       	# init the pcap file for processing. 
        $self->_init_pcap();  # not required to set if already set

	# -- reset conversation counter
	$self->{conversation_index} = 0;

	# create the filter
	Net::Pcap::compile( $self->{PCAP}, \$filter_c, $filter, 1, undef );
	Net::Pcap::setfilter( $self->{PCAP}, $filter_c );

	# read all the packets
	Net::Pcap::loop( $self->{PCAP}, -1, \&_read_all_matching, [$self,$cIndex] );  # self is passed as user data

	# collect up the hostname and IP from conversation
	$self->_collect_host_ip($cIndex);

	# process data block
	$self->_normalize_conversation_data($cIndex);

	# close the network file (since we have finished our processing)
	Net::Pcap::close( $self->{PCAP} );

	return;
}

# + + + + + + + + + + + + + + + + + + + +
# +  --   S E M I - P R I V A T E   --  +
# + + + + + + + + + + + + + + + + + + + +

# +
# +  process the SYN Packets
# +
sub _proc_syn_only {
	my ($self,$header,$pack) = @_;
	# -- beware of locals
        my $fcheck;
        my $input;
	my $eth_pac;
	my $ip_pac;
	my $trans;
	my $lproto;
	my $service;
	my $idx;  # index counter

	# Ethernet Packet processing 
	$eth_pac  = NetPacket::Ethernet->decode( $pack );  # set ethernet packet 

	# IP Packet processing
	$ip_pac   = NetPacket::IP->decode( $eth_pac->{'data'} );  # 

	switch ($ip_pac->{'proto'}) {
		case   6    {  $lproto = 'tcp';  $trans = NetPacket::TCP->decode( $ip_pac->{'data'} );  }
		case  17    {  $lproto = 'upd';  $trans = NetPacket::UDP->decode( $ip_pac->{'data'} );  }
	};

	# Define a bitmask for SYN packets
	$fcheck = $trans->{'flags'} & 0x3f;

	# RETURN unless this looks like a SYN package proto
	return unless $fcheck == 0x02;

	$idx = $self->{conversation_index}++;

	# record the conversation
	$self->{'CONV'}{$idx} = {
		'parts'     => 0,
		'index'     => $idx,
		'proto'     => $lproto,  
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $trans->{'src_port'},
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $trans->{'dest_port'},
		'flags'     => $trans->{'flags'},
	};

	# figure out a service
	if(my $srvc = $PORTS->get_info($trans->{'dest_port'},$lproto)){
		$self->{'CONV'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'}; 
	}
	elsif (my $srvc = $PORTS->get_info($trans->{'src_port'},$lproto)) {
		$self->{'CONV'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'};
	}

	if($trans->{'src_port'} == 53 || $trans->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{$idx}{dns} = $self->_Net_DNS_Packet($trans);	
	}

	return;
}

# +
# +  process the SYN Packets
# +
sub _read_all_matching {
	my ($user,$header,$pack) = @_;
	# -- beware of locals
	my ($self,$cIndex) = @$user;  # deconstruct
        my $fcheck;
        my $input;
	my $eth_pac;
	my $eth_type;
	my $ip_pac;
	my $trans;
	my $lproto;
	my $service;
	my $httpd;

	# Ethernet Packet processing 
	$eth_pac  = NetPacket::Ethernet->decode( $pack );  # set ethernet packet 
#	$self->{'CONV'}{$cIndex}{eth_data} = $eth_pac->{data};

	$eth_type = _decode_eth($eth_pac);
#	$self->{'CONV'}{$cIndex}{eth_type}{$eth_type}++;

	# IP Packet processing
	$ip_pac   = NetPacket::IP->decode( $eth_pac->{'data'} );  # 
#	$self->{'CONV'}{$cIndex}{ip_data} = $ip_pac->{data};

	# Add size to set
	$self->{'CONV'}{$cIndex}{bytes} += ($ip_pac->{len} - $ip_pac->{hlen}) || 0;

	switch ($ip_pac->{'proto'}) {
		case   6    {  
			$lproto = 'tcp';  
			$trans = NetPacket::TCP->decode($ip_pac->{'data'});  
			}
		case  17    {  
			$lproto = 'upd';  
			$trans = NetPacket::UDP->decode($ip_pac->{'data'});  
			}
		else {  printf("UNKNOWN TYPE: %d\n",$ip_pac->{'proto'}); }
	};

	# Define a bitmask for SYN packets
	$fcheck = $trans->{'flags'} & 0x3f;

	$self->{'CONV'}{$cIndex}{trans_data} = $trans->{data};

	# RETURN if this looks like a SYN package proto, we're already processed it.
	return if $fcheck == 0x02;

	# increment the number of parts in this conversation
	$self->{'CONV'}{$cIndex}{parts}++;

	# RETURN unless this is some type of IP 
	return unless $eth_type eq 'IP'; 

	# Try to HTTP parse everything.. set https as tag for port 443, use http for everything else
	switch ($trans->{'dest_port'}) {
		case   443   { $httpd = _http('https',$trans); }
		else         { $httpd = _http('http',$trans);  }
	};

	if($httpd) {
		# attempt to integrat this into the conversation block
		foreach my $key (keys %$httpd) {
			if($key eq 'data'){
				$self->{'CONV'}{$cIndex}{$key} .= $httpd->{$key};  # append
			}
			else {
				$self->{'CONV'}{$cIndex}{$key} ||= $httpd->{$key} || '';  # set if not yet set.
			}
		}
	}
	
	# send off some stuff to the DNS parser if it looks like DNS traffic

	if($trans->{'src_port'} == 53 || $trans->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{$cIndex}{dns} = $self->_Net_DNS_Packet($trans);	
	}

	return;
}

# +
# +  --
# +
sub _Net_DNS_Packet {
	my ($self,$dns_pac) = @_;
	my $dns = Net::DNS::Packet->new(\$dns_pac);

	# Decode the DNS
	my $header   = $dns->header;
	my @question = $dns->question;
	my @answer   = $dns->answer;

	for my $ans (@answer) {
		if($ans->string =~ /([a-z0-9\._-]+)\.\t.*\tIN\tA\t(\d+\.\d+\.\d+\.\d+)$/i){
			my $hostname = $1;
			my $ip       = $2;
			# set to DNS lookup
		}
	}

	return;
}

# +
# +  HTTP Packet Processing
# +
sub _http {
	my ($prefix,$trans) = @_;
	# -- beware of locals
	my $checked = 0;
	my @items;
	my $HTTPD;  # storage of stuffs found
	my $buffer = '';

	return unless @items = split (/\n|\r\n|\r/,$trans->{data});

	foreach my $item (@items) {
		if ($item =~ /^GET\s+(.*)\s+HTTP\/1/ )      { 
			$HTTPD->{action} = 'GET';
			$HTTPD->{uri}    = $1;
			next;
		}
		if ($item =~  /^POST\s+(.*)\s+HTTP\/1/ )      {	
			$HTTPD->{action} = 'POST';
			$HTTPD->{uri}    = $1;
			next;
		}
		if ($item =~  /^Location:\s+(.*)\s+HTTP\/1/i )      {
			$HTTPD->{action} = 'GET';
			$HTTPD->{url} = $1; 
			next;
		}
		if ($item =~  /^Host:\s+(.*)/ )      {
			$HTTPD->{host} = _trim_hostname($1);
			next;
		}
		if ($item =~  /^Content-Type:\s+(.*)/i )      {
			$HTTPD->{'Content-Type'} = $1;
			next;
		}
		if ($item =~  /^(Content\-.*):\s+(.*)/i )      {
			$HTTPD->{$1} = $2;
			next;
		}
		if ($item =~  /^Accept-Encoding:\s+(.*)/i )      {
			$HTTPD->{'Accept-Encoding'} = $1;
			next;
		}
		if ($item =~  /^User-Agent:\s+(.*)/ )      {
			$HTTPD->{'User-Agent'} = $1;
			next;
		}
		if ($item =~  /^Server:\s+(.*)/ )      {
			$HTTPD->{'Server'} = $1;
			next;
		}
		if ($item =~  /^Date:\s+(.*GMT)/ )      {
			$HTTPD->{'Date'} = $1;			
			next;
		}
		if ($item =~  /^Expires:\s+(.*GMT)/ )      {
			$HTTPD->{'Expires'} = $1;
			next;
		}
		if ($item =~  /^Last-Modified:\s+(.*)/ )      {
			$HTTPD->{'Last-Modified'} = $1;
			next;
		}
		if ($item =~  /^(Accept.*):\s(.*)/ )      {
			$HTTPD->{$1} = $2;
			next;
		}
		if ($item =~  /^(X-[a-z0-9\-]+):\s(.*)/i )      {
			$HTTPD->{$1} = $2;
			next;
		}
		if ($item =~  /^(Pragm[a-z0-9\-]+):\s(.*)/i )      {
			$HTTPD->{$1} = $2;
			next;
		}
		if ($item =~  /^(Alternate[a-z0-9\-]+):\s(.*)/i )      {
			$HTTPD->{$1} = $2;
			next;
		}
		if ($item =~  /^Cache-Control:\s.*/ )      {
			next;
		}
		if ($item =~  /^Keep-Alive:\s.*/ )      {
			next;
		}
		if ($item =~  /^Connection:\s+.*/ )      {
			next;
		}
		if ($item =~  /^Status:\// )      {
			next;
		}
		if ($item =~  /^HTTP\// )      {
			next;
		}
		chomp($item); # remove any extraneous crap
		$HTTPD->{data} .= $item."\n" if $item;
	}

	# Complete the assmblies
        # Get/Set host if not set
        #$host         = _get_ip_host($ip);
        $HTTPD->{url}  = sprintf('%s://%s%s',$prefix,$HTTPD->{host},$HTTPD->{uri}) if $HTTPD->{host}; 
        #$type         = _guess_type($uri);

	return $HTTPD;
}

# +
# +  HTTP Packet Processing
# +
sub _collect_host_ip {
	my($self,$cIndex) = @_;

#	printf("%s CONV:[%d]\n%s\n",(caller(0))[3],$cIndex,Dumper $self->{CONV}{$cIndex});

	return;
}

# +
# +
# +
sub _normalize_conversation_data {
	my($self,$cIndex) = @_;
	# shunt the data unless this looks like a payload
	$self->{CONV}{$cIndex}{data} = undef unless Pcap::ContentType::is_payload($self->{CONV}{$cIndex}{'Content-Type'});

	return;
}

# +
# +  initialize the pcap handle, with passed infile name
# +  function force overrides the any setting in $self->{infile} 
# +
sub _init_pcap {
	my($self) = @_;
	# -- beware of locals
	my $err;

	# set infile if exists
	die(sprintf("Unable to locate and/or open pcap input file '%s'\n",$self->{infile})) unless -e $self->{infile};  

	# start reading the file
	return $self->{PCAP} = Net::Pcap::open_offline( $self->{infile}, \$err );
}

# +
# +   translate the ethernet protocol mask to human readable knowledge
# +
sub _decode_eth {
	my($eth_pac) = @_;

        switch( $eth_pac->{type} ) {
                case ETH_TYPE_IP        { return 'IP'; }
                case ETH_TYPE_ARP       { return 'ARP'; }
                case ETH_TYPE_APPLETALK { return 'APPLETALK'; }
                case ETH_TYPE_SNMP      { return 'SNMP'; }
                case ETH_TYPE_IPv6      { return 'IPv6'; }
                case ETH_TYPE_PPP       { return 'PPP'; }
                else                    { return 'other'; }
        }

	return undef;
}

# +
# +  trim hostname
# +
sub _trim_hostname {
	my ($hostname) = @_;
	chomp($hostname);

	if($hostname =~ /([a-z0-9\-_\.]+):.*/i){
		return $1;
	}
	return $hostname;
}


1; 

