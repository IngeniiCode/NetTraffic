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

	# Init Pcap handle
	printf("Use pcap file %s\n",$infile);
	$self->_init_pcap($infile || $self->{infile});  # not required to set if already set

	# COLLECT THE UDP PACKETS
	$self->loop_udp();

	# COLLECT THE TCP PACKETS
#	$self->loop_tcp();

	# close the network file (since we have finished our processing)
	Net::Pcap::close( $self->{PCAP} );

	return;
}


# +
# +  initialize the pcap handle, with passed infile name.
# +  function force overrides the any setting in $self->{infile} 
# +
sub _init_pcap {
	my($self,$infile) = @_;
	# -- beware of locals
	my $err;

	# set infile if exists
	die(sprintf("Unable to locate and/or open pcap input file '%s'\n",$infile)) unless -e $infile;  

	# start reading the file
	if($self->{PCAP} = Net::Pcap::open_offline( $infile, \$err )){

		# save file for reference
		$self->{infile} = $infile;

		return  $infile;
	}

	return undef;  # this failed.
}


# +
# +   UDP Packet Processing
# +
sub loop_udp {
	my($self) = @_;
	# -- beware of locals
	my $filter_c;  # holder for compiled filter

	# -- reset conversation counter
	$self->{conversation_index} = 0;
	
	# create the filter
	Net::Pcap::compile( $self->{PCAP}, \$filter_c, 'udp', 1, undef );
	Net::Pcap::setfilter( $self->{PCAP}, $filter_c );

	# read all the packets
	Net::Pcap::loop( $self->{PCAP}, -1, \&_proc_udp, $self );  # self is passed as user data

	return;
}


# +
# +   TCP Packet Processing
# +
sub loop_tcp {
	my($self) = @_;
	# -- beware of locals
	my $filter_c;  # holder for compiled filter

	# create the filter
	Net::Pcap::compile( $self->{PCAP}, \$filter_c, 'tcp', 1, undef );
	Net::Pcap::setfilter( $self->{PCAP}, $filter_c );

	# read all the packets
	Net::Pcap::loop( $self->{PCAP}, -1, \&read_all_packets, '' ); 
	
	return;
}

	
# + + + + + + + + + + + + + + + + + + + +
# +  --   S E M I - P R I V A T E   --  +
# + + + + + + + + + + + + + + + + + + + +

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
	$udp_pac  = NetPacket::TCP->decode( $ip_pac->{'data'} );

	# record the conversation
	my $conv = {
		'src_ip'    => $ip_pac->{'src_ip'},
		'src_port'  => $udp_pac->{'src_port'},
		'src_srvc'  => $PORTS->get_info($udp_pac->{'src_port'},'udp'), 
		'dest_ip'   => $ip_pac->{'dest_ip'},
		'dest_port' => $udp_pac->{'dest_port'},
		'dest_srvc' => $PORTS->get_info($udp_pac->{'dest_port'},'udp'),
		'flags'     => $udp_pac->{'flags'},
		'hostname'  => '',
	};
	printf("CONV [%02d]: %s\n",$idx,Dumper $conv);
	$self->{'CONV'}{'UDP'}{$idx} = $conv;

	#if($udp_pac->{'src_port'} == 53 || $udp_pac->{'dest_port'} == 53) {
	if($udp_pac->{'src_port'} == 53) {
		# DNS!
		my $resp = $self->_Net_DNS_Packet($udp_pac);
	}

	return;
}

# +
# +  --
# +
sub _Net_DNS_Packet {
	my ($self,$dns_pac) = @_;
	my $dns = Net::DNS::Packet->new(\$dns_pac);
printf("DNS: %s\n",Dumper $dns);

	# Decode the DNS
	my $header   = $dns->header;
	my @question = $dns->question;
	my @answer   = $dns->answer;

printf("%s\n%s\n%s\n",$header,Dumper @question,@answer);

	for my $ans (@answer) {
		if($ans->string =~ /([a-z0-9\._-]+)\.\t.*\tIN\tA\t(\d+\.\d+\.\d+\.\d+)$/i){
			my $hostname = $1;
			my $ip       = $2;
printf("DNS: %s -> %s\n",$hostname,$ip);
			# set to DNS lookup
		}
	}

	return;
}


1; 

