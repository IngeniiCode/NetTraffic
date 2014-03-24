# =============================
  package Pcap::Conversation;
# =============================
use strict;

# =============================
#  Define required modules
# =============================
use Net::Pcap;
use Net::DNS::Packet;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use Pcap::PortService; 
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

printf("%s\n",uc((caller(0))[3]));

	foreach my $cIndex (keys %{$self->{'CONV'}{SYN}}){
		my $filter;
		my $filter_c;  # hold the compiled filter
		printf("IDX: %06d\n",$cIndex); 
		my $C = $self->{'CONV'}{SYN}{$cIndex};  # localize this thing
		# Build a filter based on this conversations knows
		# read entire conversation
		# construct a filter
		$filter = sprintf('tcp and (host %s and host %s) and (port %d and port %d)',$C->{src_ip},$C->{dest_ip},$C->{src_port},$C->{dest_port});
printf("FILTER: %s\n",$filter);
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

printf("%s('%s');\n",uc((caller(0))[3]),$proto);

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

printf("%s('%s','%s');\n",uc((caller(0))[3]),$cIndex,$filter);

       	# init the pcap file for processing. 
        $self->_init_pcap();  # not required to set if already set

	# -- reset conversation counter
	$self->{conversation_index} = 0;

	# create the filter
	Net::Pcap::compile( $self->{PCAP}, \$filter_c, $filter, 1, undef );
	Net::Pcap::setfilter( $self->{PCAP}, $filter_c );

	# read all the packets
	Net::Pcap::loop( $self->{PCAP}, -1, \&_read_all_matching, [$self,$cIndex] );  # self is passed as user data

	# close the network file (since we have finished our processing)
	Net::Pcap::close( $self->{PCAP} );

	exit;  # TEMPORARY DEBUGGING STRATEGY

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
	$self->{'CONV'}{SYN}{$idx} = {
		'index'     => $idx,
		'proto'     => $lproto,  
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $trans->{'src_port'},
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $trans->{'dest_port'},
		'flags'     => $trans->{'flags'},
		'hostname'  => '',
	};

	# figure out a service
	if(my $srvc = $PORTS->get_info($trans->{'dest_port'},$lproto)){
		$self->{'CONV'}{'SYN'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'}; 
	}
	elsif (my $srvc = $PORTS->get_info($trans->{'src_port'},$lproto)) {
		$self->{'CONV'}{'SYN'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'};
	}

	if($trans->{'src_port'} == 53 || $trans->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{'SYN'}{$idx}{dns} = $self->_Net_DNS_Packet($trans);	
	}

	return;
}

# +
# +  process the SYN Packets
# +
sub _read_all_matching {
	my ($self,$cIndex,$header,$pack) = @_;
	# -- beware of locals
        my $fcheck;
        my $input;
	my $eth_pac;
	my $ip_pac;
	my $trans;
	my $lproto;
	my $service;
	my $idx;  # index counter

printf("%s('%s',%d,'%s','%s');\n",uc((caller(0))[3]),$self,$cIndex,$header,$pack);
	return;

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


	# record the conversation
	$self->{'CONV'}{SYN}{$idx} = {
		'index'     => $idx,
		'proto'     => $lproto,  
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $trans->{'src_port'},
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $trans->{'dest_port'},
		'flags'     => $trans->{'flags'},
		'hostname'  => '',
	};

	# figure out a service
	if(my $srvc = $PORTS->get_info($trans->{'dest_port'},$lproto)){
		$self->{'CONV'}{'SYN'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'}; 
	}
	elsif (my $srvc = $PORTS->get_info($trans->{'src_port'},$lproto)) {
		$self->{'CONV'}{'SYN'}{$idx}{'service'} = $srvc->{'description'} || $srvc->{'service'};
	}

	if($trans->{'src_port'} == 53 || $trans->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{'SYN'}{$idx}{dns} = $self->_Net_DNS_Packet($trans);	
	}

	return;
}


# +
# +  process the UDP Packets
# +
sub _proc_udp {
	my ($self,$header,$pack) = @_;
	# -- beware of locals
        my $fcheck;
        my $input;
	my $eth_pac;
	my $ip_pac;
	my $udp_pac;
	my $idx = $self->{conversation_index}++;

	# Ethernet Packet processing 
	$eth_pac  = NetPacket::Ethernet->decode( $pack );  # set ethernet packet 

	# IP Packet processing
	$ip_pac   = NetPacket::IP->decode( $eth_pac->{'data'} );  # 

	# UDP Packet processing
	$udp_pac  = NetPacket::UDP->decode( $ip_pac->{'data'} );

	# record the conversation
	$self->{'CONV'}{'UDP'}{$idx} = {
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $udp_pac->{'src_port'},
		'src_srvc'  => $PORTS->get_info($udp_pac->{'src_port'},'udp'), 
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $udp_pac->{'dest_port'},
		'dest_srvc' => $PORTS->get_info($udp_pac->{'dest_port'},'udp'),
		'flags'     => $udp_pac->{'flags'},
		'hostname'  => '',
	};

	if($udp_pac->{'src_port'} == 53 || $udp_pac->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{'UDP'}{$idx}{dns} = $self->_Net_DNS_Packet($udp_pac);	
	}

	return;
}

# +
# +  process the TCP Packets
# +
sub _proc_tcp {
	my ($self,$header,$pack) = @_;
	# -- beware of locals
        my $fcheck;
        my $input;
	my $eth_pac;
	my $ip_pac;
	my $tcp_pac;
	my $idx = $self->{conversation_index}++;

	# Ethernet Packet processing 
	$eth_pac  = NetPacket::Ethernet->decode( $pack );  # set ethernet packet 

	# IP Packet processing
	$ip_pac   = NetPacket::IP->decode( $eth_pac->{'data'} );  # 

	# UDP Packet processing
	$tcp_pac  = NetPacket::TCP->decode( $ip_pac->{'data'} );

	# record the conversation
	$self->{'CONV'}{'TCP'}{$idx} = {
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $tcp_pac->{'src_port'},
		'src_srvc'  => $PORTS->get_info($tcp_pac->{'src_port'},'tcp'), 
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $tcp_pac->{'dest_port'},
		'dest_srvc' => $PORTS->get_info($tcp_pac->{'dest_port'},'tcp'),
		'flags'     => $tcp_pac->{'flags'},
		'hostname'  => '',
	};

	if($tcp_pac->{'src_port'} == 53 || $tcp_pac->{'dest_port'} == 53) {
		# DNS!
		$self->{'CONV'}{'TCP'}{$idx}{dns} = $self->_Net_DNS_Packet($tcp_pac);	
	}

	return;
}

# +
# +  --
# +
sub _Net_DNS_Packet {
	my ($self,$dns_pac) = @_;
	my $dns = Net::DNS::Packet->new(\$dns_pac);
#printf("DNS: %s\n",Dumper $dns);

	# Decode the DNS
	my $header   = $dns->header;
	my @question = $dns->question;
	my @answer   = $dns->answer;

#printf("%s\n%s\n%s\n",$header,Dumper @question,@answer);

	for my $ans (@answer) {
		if($ans->string =~ /([a-z0-9\._-]+)\.\t.*\tIN\tA\t(\d+\.\d+\.\d+\.\d+)$/i){
			my $hostname = $1;
			my $ip       = $2;
#printf("DNS: %s -> %s\n",$hostname,$ip);
			# set to DNS lookup
		}
	}

	return;
}


# +
# +  initialize the pcap handle, with passed infile name.
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

1; 

