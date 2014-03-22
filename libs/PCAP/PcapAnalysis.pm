# =============================
  package Pcap::Analysis;
# =============================


# =============================
#  Define required modules
# =============================
use strict;
use Net::DNS;
use Net::DNS::Resolver;
use Switch;
# -- Networking Packages --
use Net::Pcap;
use NetPacket::Ethernet qw(:ALL);
use NetPacket::ICMP qw(:ALL);
use NetPacket::IP qw(:ALL);
use NetPacket::TCP qw(:ALL);
use NetPacket::UDP qw(:ALL);
# -- depricated --
#use NetPacket::ARP qw(:ALL);
#use NetPacket::IGMP qw(:ALL);
use Data::Dumper;

# =============================
#  Define global scoped variables
# =============================
my $DISABLED          = 0;
my $ENABLED           = 1;
my $READ_ALL_PKTS     = -1;
my $DEFAULT_LIST_SIZE = 10;
my $UNKNOWN_ERROR     = -1;
my $WSformat          = {};
my $packet_id         = 0;

# -- data
my $REPORT  = {
	FRAMES   => {},
	DNS      => {},
	TRAFFIC  => {},
	ACKCHAIN => {},  # try to chain together ACKS
	MEDIA    => {},  # media frames
	PAYLOAD  => {},  # some type of instructions payload
};
my $DNS   = {};
my $Resolver;

my $fBase   = '';  # path to intake file, drop report in same location.

# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  + 
# + + + + + + + + + + + + + + + + + + + +
sub new {
	my $class = shift;
	my $self  = { @_ };
	keys($REPORT->{FRAMES})   = 10000;
	keys($REPORT->{DNS})      = 100;
	keys($REPORT->{TRAFFIC})  = 1000;
	keys($REPORT->{ACKCHAIN}) = 1000;
	keys($REPORT->{MEDIA})    = 100;
	keys($DNS)                = 100;  

	# Setup the resolver
	$Resolver = Net::DNS::Resolver->new(
		udp_timeout => 2,
		retry       => 1,
	);
	
	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  accept filename and process into data profiles
# +
sub get_report {
	return $REPORT;
}

# +
# +  --  accept filename and process into data profiles
# +
sub process_file {
	my($self,$filename) = @_;

	# +  --  open file
	$self->_loop($self->_open_file($filename));

	# +  --  finalize
	_finalize();

	printf("ACKCHAIN %s\n",Dumper $REPORT->{ACKCHAIN});

	return;
}

# +
# +  --  open file and set to PCAP reference 
# +
sub _open_file {
	my($self,$file) = @_;

	$fBase = $file;

	my $io_error;
	my $pcap = pcap_open_offline( $file, \$io_error ) || die( __LINE__,  "Can't read $file: $io_error" );
	my $type = pcap_datalink($pcap);
		
	return ($pcap,$type);
}

# +
# +  --  set call back and loop records 
# +
sub _loop {
	my($self,$pcap,$type) = @_;

	$REPORT->{pcap_type} = $type;

	# +  Loop through the pcap data, shove data down callback pipe 'process_pcap()'
	pcap_loop( $pcap, -1, \&process_pcap, $type );

	# +  close loop / end
	pcap_close($pcap);
	
	return;
}

# +
# +  --  define the callback 
# +
sub process_pcap {
	my($type,$header,$raw) = @_;
	$packet_id++;  # increment packet counter
#	printf("%s(%s,%s,\$raw);\n",uc((caller(0))[3]),$type,$header);

	# record package timestamps
	_timestamps($header->{tv_sec});

	# start packet processing
	_NetPacket_Ethernet($raw) if $type == DLT_EN10MB;

	# Processing completed

	return;
}

# +
# +  --  NetPacket::Ethernet  processing 
# +
sub _NetPacket_Ethernet {
	my ($eth_pkt) = NetPacket::Ethernet->decode(shift);
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame
	
	my $eth_data  = $eth_pkt->{data};  # $payload contains the actual message
	my $eth_type;

        switch( $eth_pkt->{type} ) {
                case ETH_TYPE_IP        { $eth_type = 'IP'; }
                case ETH_TYPE_ARP       { $eth_type = 'ARP'; }
                case ETH_TYPE_APPLETALK { $eth_type = 'APPLETALK'; }
                case ETH_TYPE_SNMP      { $eth_type = 'SNMP'; }
                case ETH_TYPE_IPv6      { $eth_type = 'IPv6'; }
                case ETH_TYPE_PPP       { $eth_type = 'PPP'; }
                else                    { $eth_type = 'other'; }
        }

	$$FRAME->{ETH_TYPE} = $eth_type;

	# Save MAC Address Data:
        $$FRAME->{MAC} = {
                src_mac  => $eth_pkt->{src_mac},
                dest_mac => $eth_pkt->{dest_mac}
        };

	# If packet is of type IP, pass to IP processor
	_NetPacket_IP($eth_data) if $eth_type eq 'IP';

	return;
}

# +
# +  --  main packet processing 
# +
sub _NetPacket_IP {
	my ($ip_pkt) = NetPacket::IP->decode(shift); 
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame
	
	my $ip_data  = $ip_pkt->{data};  # $payload contains the actual message
	
	$$FRAME->{SIZE} = ($ip_pkt->{len} - $ip_pkt->{hlen}) || 0;
	$$FRAME->{IP} = { 
		proto   => $ip_pkt->{proto}   || 0,
		src_ip  => $ip_pkt->{src_ip}  || 0,
		dest_ip => $ip_pkt->{dest_ip} || 0,
	};
	#$REPORT->{ACKCHAIN}{$acknum}{type}          ||= $$FRAME->{TYPE};

	# reset the cache 

	# flag direction of traffic
	$$FRAME->{FLOW} = ($ip_pkt->{src_ip} =~ /^192\.168\./) ? 'OUTBOUND' : 'INBOUND';

	#  Determine next parsing package based on protocol type
	switch( $ip_pkt->{proto} ) {
#		case IP_PROTO_ICMP    {
#			_NetPacket_ICMP($ip_data); }
		case IP_PROTO_TCP     {
			_NetPacket_TCP($ip_data); }
		case IP_PROTO_UDP     {
			_NetPacket_UDP($ip_data); }
	};

	return;
}

# +
# +  --   
# +
sub _NetPacket_ICMP {
	my $icmp_pkt = NetPacket::ICMP->decode(shift);
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame
	
	my $type;

	$$FRAME->{TYPE} = 'ICMP';

	switch( $icmp_pkt->{type} ) {
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
	
       	$$FRAME->{ICMP}{type} = $type; 

	return;
}

# +
# +  --   
# +
sub _NetPacket_TCP {
	my $tcp_pkt = NetPacket::TCP->decode(shift);
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame

	$$FRAME->{TYPE} = 'TCP';

	my $tcp_data = $tcp_pkt->{data};
	my $flag     = '';
	my $ip       = $$FRAME->{IP}{src_ip};
	my $port     = $tcp_pkt->{src_port};
	my $host     = _get_ip_host($ip);
	my $acknum   = $tcp_pkt->{acknum};

	$$FRAME->{TCP} = {
		host      => $host,
		src_ip    => $$FRAME->{IP}{src_ip},
		dest_ip   => $$FRAME->{IP}{dest_ip},
		src_port  => $tcp_pkt->{src_port},
		dest_port => $tcp_pkt->{dest_port},
		seqnum    => $tcp_pkt->{seqnum},
		acknum    => $tcp_pkt->{acknum},
		winsize   => $tcp_pkt->{winsize},
	};

	$REPORT->{ACKCHAIN}{$acknum}{acknum} = $tcp_pkt->{acknum} || -1;
	$REPORT->{ACKCHAIN}{$acknum}{type}   = $$FRAME->{TYPE};

	$REPORT->{TRAFFIC}{IP}{$ip}{$port}{bytes} += $$FRAME->{SIZE}||0;
	$REPORT->{TRAFFIC}{IP}{$ip}{$port}{host}   = $host;

	# Determine further processing:
	if ( $tcp_pkt->{dest_port} == 80 || $tcp_pkt->{src_port} == 80 ) {
        	_http('http',$tcp_data);
	}

	if ( $tcp_pkt->{dest_port} == 443 || $tcp_pkt->{src_port} == 443 ) {
	       	_http('https',$tcp_data);
	}

	# --  hand off packet to DNS parser for further exam.
	if ( $tcp_pkt->{dest_port} == 53 || $tcp_pkt->{src_port} == 53 ) {
		_Net_DNS_Packet($tcp_data);
	}

	_tcpip($tcp_data);

#	printf("%s\t%s\n",uc((caller(0))[3]),$tcp_data) if $tcp_data;

	return;
}

# +
# +  --   
# +
sub _NetPacket_UDP {
	my $udp_pkt = NetPacket::UDP->decode(shift);
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame

	my $udp_data = $udp_pkt->{data};

	$$FRAME->{TYPE}           = 'UDP';
	$$FRAME->{SIZE}           = $udp_pkt->{len};
	$$FRAME->{UDP}{src_port}  = $udp_pkt->{src_port};
	$$FRAME->{UDP}{dest_port} = $udp_pkt->{dest_port};

	# Check to see if it looks like DNS traffic and parse if so
	if ( $udp_pkt->{dest_port} == 53 || $udp_pkt->{src_port} == 53 ) {
		_Net_DNS_Packet($udp_data);	
	}

	return; # nothing else of interest to us, here 	
}

# +
# +  --   
# +
sub _Net_DNS_Packet {
        my $pkt = shift;
        my $dns = Net::DNS::Packet->new(\$pkt);
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame

	$$FRAME->{TYPE} = 'DNS';

	# Decode the DNS
        my $header   = $dns->header;
        my @question = $dns->question;
        my @answer   = $dns->answer;

	for my $ans (@answer) {
		if($ans->string =~ /([a-z0-9\._-]+)\.\t.*\tIN\tA\t(\d+\.\d+\.\d+\.\d+)$/i){
			my $hostname = $1;
			my $ip       = $2;
			# set to DNS lookup
			$REPORT->{DNS}{HOST_to_IP}{$hostname}  = $ip if $ip;
			$REPORT->{DNS}{IP_to_HOST}{$ip}        = $hostname if $hostname;
			# set to report
			$REPORT->{FRAMES}{$packet_id}{DNS} = {	
				hostname => $hostname,
				ip       => $ip,
			};
		}
	}

	return;
}

# +
# +  TCP/IP Packet Processing
# +
sub _tcpip {
	my ($data) = @_;
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame

	my @items = split (/\n|\r\n|\r/,$data);

	my $acknum        = $$FRAME->{TCP}{acknum};
	my $content_type  = $REPORT->{ACKCHAIN}{$acknum}{content_type} || '';
	my $encoding_type = $REPORT->{ACKCHAIN}{$acknum}{encoding_type} || ''; 

printf("TCP/IP data:%s\n",Dumper @items);

	foreach my $item (@items) {
		if ($item =~ /^Content-Type:\s+(.*)/i) {
			$content_type = $1;
		}
		if ($item =~ /^Content-Encoding:\s+(.*)/i) {
			$encoding_type = $1;
		}
	}

	$REPORT->{ACKCHAIN}{$acknum}{content_type}  ||= $content_type;
	$REPORT->{ACKCHAIN}{$acknum}{encoding_type} ||= $encoding_type;
	$REPORT->{ACKCHAIN}{$acknum}{type}          ||= $$FRAME->{TYPE};

	#  Set type an encoding
	$REPORT->{TRAFFIC}{TYPE}{$content_type}{bytes} += $$FRAME->{SIZE}||0;
	$REPORT->{TRAFFIC}{ENC}{$encoding_type}{bytes} += $$FRAME->{SIZE}||0;

	return;
}

# +
# +  HTTP Packet Processing
# +
sub _http {
	my ($prefix,$data) = @_;
	my $FRAME = \$REPORT->{FRAMES}{$packet_id};  # localize the frame

	my @items   = split (/\n|\r\n|\r/,$data);
	my $acknum  = $$FRAME->{TCP}{acknum};
	my $checked = 0;
	my $host    = '';
	my $url     = '';
	my $uri     = '';
	my $agent   = '';
	my $action  = '';
        my $type    = $REPORT->{ACKCHAIN}{$acknum}{content_type}  || '';
        my $enc     = $REPORT->{ACKCHAIN}{$acknum}{encoding_type} || '';

	$$FRAME->{TYPE} = 'HTTPD';

	foreach my $item (@items) {
		if ($item =~ /^GET\s+(.*)\s+HTTP\/1/) {
			$action   = 'GET';
			$uri    ||= $1;
                }
                if ($item =~ /^POST\s+(.*)\s+HTTP\/1/) {
			$action   = 'POST';
			$uri    ||= $1;
                }
                if ($item =~ /^Location:\s+(.*)\s+HTTP\/1/i) {
			$url ||= $1;
                }
                if ($item =~ /^Host:\s+(.*)/) {
			$host = _trim_hostname($1);
                }
		if ($item =~ /^Content-Type:\s+(.*)/i) {
			$type = $1;
		}
		if ($item =~ /^Content-Encoding:\s+(.*)/i) {
			$enc = $1;
		}
                if ($item =~ /User-Agent:\s+(.*)/) {
                        $agent = $1;
                        $agent =~ s/\(//g;
                        $agent =~ s/\)//g;
                }
		last if $checked++ > 15;	
        }

	# Record the encoding or content type on this string, if set
        $REPORT->{ACKCHAIN}{$acknum}{content_type}  ||= $type; 
        $REPORT->{ACKCHAIN}{$acknum}{encoding_type} ||= $enc; 
	$REPORT->{ACKCHAIN}{$acknum}{type}          ||= $$FRAME->{TYPE};

	#  Calculate the relevant IP, based on guessed direction
	my $src_ip  = $$FRAME->{IP}{src_ip};
	my $dest_ip = $$FRAME->{IP}{dest_ip};
	my $ip      = ($$FRAME->{FLOW} eq 'OUTBOUND') ?  $dest_ip : $src_ip;

	# Get/Set host if not set 
	$host    ||= _get_ip_host($ip);
        $url     ||= ($host) ? sprintf('%s://%s%s',$prefix,$host,$uri) : '';
	$type    ||= _guess_type($uri);

	$REPORT->{ACKCHAIN}{$acknum}{url} = $url;

	# --  HTTP data parsed
       	$$FRAME->{HTTPD} = {
		uri                => $uri,
		url                => $url,
		host               => $host,
		action             => $action,
		agent              => $agent,
		'Content-Type'     => $type,
		'Content-Encoding' => $enc,
	};

	$REPORT->{TRAFFIC}{TYPE}{$type}{bytes}  += $$FRAME->{SIZE}||0;
	$REPORT->{TRAFFIC}{ENC}{$enc}{bytes}    += $$FRAME->{SIZE}||0;
	$REPORT->{TRAFFIC}{URLS}{$url}{bytes}   += $$FRAME->{SIZE}||0;
	$REPORT->{TRAFFIC}{HOSTS}{$host}{bytes} += $$FRAME->{SIZE}||0;
	
	$REPORT->{MEDIA}{$packet_id}   = $type if _is_media($type);
	$REPORT->{PAYLOAD}{$packet_id} = $type if _is_payload($type);

	#printf("%s(%s,\$raw);\n%s",uc((caller(0))[3]),$prefix,$data) if $data;

        return;
}

# +
# +  --  record the timestamps 
# +
sub _timestamps {
	my($timestamp) = @_;

	#
	# Capture Start and End time frames
	#
	$REPORT->{start_time} = $timestamp if !$REPORT->{start_time} || $timestamp < $REPORT->{start_time};
	$REPORT->{stop_time}  = $timestamp if !$REPORT->{stop_time}  || $timestamp > $REPORT->{stop_time};

	return;
}

# +
# +  --  Finalize Reporting 
# +
sub _finalize {

	# Make timestamps human readable
	$REPORT->{start_time} = gmtime($REPORT->{start_time});
	$REPORT->{stop_time}  = gmtime($REPORT->{stop_time});
	$REPORT->{packets}    = $packet_id;

	return;
}

# +
# +  get hostname IP address(es)
# +
sub _get_ip_host {
	my($ip) = @_;
	return $REPORT->{DNS}{IP_to_HOST}{$ip} if $REPORT->{DNS}{IP_to_HOST}{$ip};
	return $DNS->{$ip} if defined($DNS->{$ip});
	#printf("GET_IP_HOST(%s)\n",$ip);
	if (my $pkt = $Resolver->query($ip)) {
		for my $answer ( $pkt->answer() ) {
			my $type = $answer->type();
			if ($type eq "PTR") {
            			$DNS->{$ip} = $answer->ptrdname();
			} 
			elsif ($type eq "A") {
            			$DNS->{$ip} = $answer->name();
			}
		}
	}
	return $DNS->{$ip} ||= '';
}

# +
# +  get hostname IP address(es)
# +
sub _get_host_ip {
        my($host) = @_;
        return $REPORT->{DNS}{HOST_to_IP}{$host} if $REPORT->{DNS}{HOST_to_IP}{$host};
	return $DNS->{$host} if $DNS->{$host};
        if(my $ip = inet_ntoa(inet_aton($host))){
		$DNS->{$host} = $ip;
        	$REPORT->{DNS}{HOST_to_IP}{$host} = $ip;
        	$REPORT->{DNS}{IP_to_HOST}{$ip} = $host unless $REPORT->{DNS}{IP_to_HOST}{$ip};
	}
        return $DNS->{$host}; 
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

# +
# +  try to determine content type
# +
sub _guess_type {
	my($url) = @_;
	
	# guess at content type if not defined --- this will need to be extended!!
	switch($url) {
		case { $_[0] =~  /\.html?\b/i }      { return 'text/html'; }
		case { $_[0] =~  /\.js\b/i }         { return 'text/javascript'; }
		case { $_[0] =~  /\.jsp\b/i }        { return 'text/java-servelet'; }
		case { $_[0] =~  /\.asm\b/i }        { return 'text/x-asm'; }
		case { $_[0] =~  /\.json\b/i }       { return 'text/json'; }
		case { $_[0] =~  /\.xml\b/i }        { return 'text/xml'; }
		case { $_[0] =~  /\.asp\b/i }        { return 'application/asp'; }
		case { $_[0] =~  /\.php[3-6]?\b/i }  { return 'application/php'; }
		case { $_[0] =~  /\.cgi\b/i }        { return 'application/cgi'; }
		case { $_[0] =~  /\.do\b/i }         { return 'application/octet-stream'; }
		case { $_[0] =~  /\.ico\b/i }        { return 'image/icon'; }
		case { $_[0] =~  /\.png\b/i }        { return 'image/png'; }
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
		else                                 { return; }
	}

	return;
}

# +
# +  try to determine if this is media content
# +
sub _is_media {
	my($type) = @_;
	
	# guess at content type if not defined --- this will need to be extended!!
	switch($type) {
		case { $_[0] =~  /video/i }   { return 1; }
		case { $_[0] =~  /audio/i }   { return 1; }
		case { $_[0] =~  /stream/i }  { return 1; }
	};
	
	return;
}

# +
# +  try to determine if this looks like a data payload
# +
sub _is_payload {
	my($type) = @_;
	
	# guess at content type if not defined --- this will need to be extended!!
	switch($type) {
		case { $_[0] =~  /json/i }   { return 1; }
		case { $_[0] =~  /xml/i }    { return 1; }
	};
	
	return;
}

# +
# =============================
1;
