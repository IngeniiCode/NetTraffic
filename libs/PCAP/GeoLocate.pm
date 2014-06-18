# =============================
  package Pcap::GeoLocate;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
use WWW::Mechanize;
use Mojo::DOM;
use Switch;
use Data::Dumper;
# - - - - - - - - - - - - - - -

# =============================
#  Define global scoped variables
# =============================
my $url = 'http://www.find-ip-address.org/ip-address-locator.php';
my $parse_config = {
	start => '"S", tagname, attr, dtext',
	text  => 'dtext',
};
my $CACHE = {}; # ip geo-located cache

# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  +
# + + + + + + + + + + + + + + + + + + + +
sub new {
        my ($class) = @_;
	my $self = {
		MECH => WWW::Mechanize->new(),
		DATA => {},
	};
	$self->{MECH}->agent_alias( 'Windows IE 6' );  #  really fake browser agent

        return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  accept filename and process into data profiles
# +
sub go {
	my ($self,$ip) = @_;
	chomp ($ip);

	return $self->{DATA} = $CACHE->{$ip} if $CACHE->{$ip};
	
	# ---  get the response
	$self->{MECH}->get($url);  # intake page
	
	# ---  submit form
	$self->{MECH}->submit_form(
		form_name => 'ip', 
		fields    => { ip  => $ip }
	);
	
	# ---  get reply
	$self->{HTML} = $self->{MECH}->content();

	# ---  parse for desired elements
	$self->_parse();

	$CACHE->{$ip} = $self->{DATA}; # store to cache to speed retrieval

	return;
}

# +
# +  --  accept filename and process into data profiles
# +
sub get_content_raw {
	my($self) = @_;
	return $self->{HTML};
}

# +
# +  --  accept filename and process into data profiles
# +
sub get_data {
	my($self) = @_;
	return $self->{DATA};
}

# +
# +  --  accept filename and process into data profiles
# +
sub get_country {
	my($self) = @_;
	return $self->{DATA}{country}||'~unknown~';
}

# +
# +  --  accept filename and process into data profiles
# +
sub get_mojo_text_all {
	my($self) = @_;
	return $self->{TEXT};
}

# +
# +
# +
sub get_geoblock {
	my($self) = @_;

	return sprintf("%s\n - - - - - - - - - - - - - - -\n%s\n%s\n%s",
		$self->{DATA}{org},
		$self->{DATA}{isp},
		$self->{DATA}{host},
		$self->{DATA}{country}
	);
}

# +
# +  --  accept filename and process into data profiles
# +
sub _parse {
	my($self) = @_;
	
	#  get your Mojo ON!
	$self->{DOM} = Mojo::DOM->new($self->{HTML});

	# find the start of the meat
	my $ct = 0;

	$self->_parse_bold();
	$self->_parse_strong();

	$self->{TEXT} = $self->{DOM}->all_text;
	
	return;
}

# +
# +  --  
# +
sub _parse_bold {
	my ($self) = @_;
	for my $b ($self->{DOM}->find('b')->each) {
		$self->_parse_block($b);
	}
	return;
}

# +
# +  --  
# +
sub _parse_strong {
	my ($self) = @_;
	for my $str ($self->{DOM}->find('strong')->each) {
		$self->_parse_block($str);
	}
	return;
}

# +
# +  --  
# +
sub _parse_block {
	my ($self,$elem) = @_;
	my $tag = $elem->text || $elem->content;
#	printf("TAG: %s\n",$tag);

#        ELEM: (IP Address)
#        ELEM: (Hostname)
#        ELEM: (IP Address Region)
#        ELEM: (IP Address City)
#        ELEM: (IP Address Latitude)
#        ELEM: (IP Address Longtitude)
#        ELEM: (IP Country Name)
#        ELEM: (IP Country Code)
#        ELEM: (IP to Dec)
#        ELEM: (IP to Hex)
#        ELEM: (IP to Bin)
#        ELEM: (Time zone for 95.142.194.48)
#        ELEM: (Local time zone for 95.142.194.48)
#        ELEM: (My Ip Address)
#        ELEM: (Free IP Locator and IP Tracker)
#        ELEM: (IP Country Capital)
#        ELEM: (IP Language)
#        ELEM: (IP Currency)
#        ELEM: (IP Country Latitude)
#        ELEM: (IP Country Longitude)
#        ELEM: (IP Address Continent)
#        ELEM: (IP Continent Code)
#        ELEM: (IP Continent Population)
#        ELEM: (IP Continent Area)
#        ELEM: (IP Continent Total Population)
#        ELEM: (IP Continent Density People)
#        ELEM: (IP Continent Latitude)
#        ELEM: (IP Continent Longitude)
#        ELEM: (IP Address Organization)
#        ELEM: (IP Address ISP)

	switch( $tag ) {
		case  /^IP Address$/                { $self->{DATA}{ip}      = $self->_get_value($elem); }
		case  /^Hostname$/                  { $self->{DATA}{host}    = $self->_get_value($elem); }
		case  /^IP Address Region$/         { $self->{DATA}{region}  = $self->_get_value($elem); }
		case  /^IP Address City$/           { $self->{DATA}{city}    = $self->_get_value($elem); }
		case  /^IP Address Latitude$/       { $self->{DATA}{lat}     = $self->_get_value($elem); }
		case  /^IP Address Longtitude$/     { $self->{DATA}{lon}     = $self->_get_value($elem); }
		case  /^IP Country Name$/           { $self->{DATA}{country} = $self->_get_value($elem); }
		case  /^IP Country Code$/           { $self->{DATA}{ccode}   = $self->_get_value($elem); }
		case  /^IP Address Organization$/i  { $self->{DATA}{org}     = $self->_get_value($elem); }
		case  /^IP Address ISP$/i           { $self->{DATA}{isp}     = $self->_get_value($elem); }
	}

	return;
}

# +
# +  --  
# +
sub _get_value {
	my($self,$elem) = @_;
	#printf("TAG: [%s]\n",$elem->content);

	# try to get next sibling
	if(my $nex = $elem->next) { 
		my $type = $nex->type;
		my $val  = $nex->text || $nex->content;  # save
		#printf("VAL:%s\t(%s)\n",$nex->type,$nex->text);
		switch( $type ) {
			case /span/  { return $val; }
			case /font/  { return $val; }
			else         { printf("ELSE: type:%s => (%s)\n",$type,$val); }
		}
	}
	#printf("GetValue: %s\n",Dumper $elem);

	return;
}

1;
