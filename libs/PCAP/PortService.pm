# =============================
  package Pcap::PortService;
# =============================
use strict;

# =============================
#  Define required modules
# =============================
use Net::IANA::Services qw(:subs);
# - - - - - - - - - - - - - - 
use Data::Dumper;  # for debugging

# =============================
#  Define  Package Variables
# =============================

# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  +
# + + + + + + + + + + + + + + + + + + + +
sub new {
        my ($class) = @_;  # ingest package name, and any args
	my $self = { };
	return bless ($self, $class); # this is what makes a reference into an object
}

# +
# +  set the fitler object will use to decode pcap
# +
sub get_info {
	my($self,$port,$type) = @_;

	my $service_info;  # undef by default

	# get preliminary port info
	if(my @services = iana_info_for_port($port,$type||'')){
		my $service = pop(@services);
		$service_info->{'service'} = $service;  # store terse service name
		# recurse and get info for the service
		if(my $info = iana_info_for_service( $service, $type)){
			$service_info->{'description'} = $info->{$port}{desc};
		}
	}
	return $service_info;
}

1; 

