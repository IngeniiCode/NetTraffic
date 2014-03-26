# =============================
  package Pcap::Whois;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
use Net::Whois::Parser;
use Data::Dumper;
# - - - - - - - - - - - - - - -

# =============================
#  Define global scoped variables
# =============================


# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  +
# + + + + + + + + + + + + + + + + + + + +
sub new {
        my ($class) = @_;
	my $self = {
		hostname => '',
		DATA     => {},
	};

        return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  accept filename and process into data profiles
# +
sub go {
	my ($self,$hostname) = @_;

	do {
		$self->{DATA} = {}; # empty
		# try to parse first time out.
		if($self->{DATA} = parse_whois( domain => $hostname )){
			# found it
			return $self->{DATA};
		}
		# Take off the front part and try again
		if($hostname =~ /[a-z0-9_\-]+\.(.*$)/i){
			$hostname = $1;  # set back the trimmed off hostname	
		}		
		else {
			$hostname = 0;
		}
	} while $hostname;
	
	return;
}

# +
# +  --  
# +
sub get_whois_raw {
	my($self) = @_;
	return $self->{DATA};
}

# +
# +  --  
# +
sub whois_domain {
	my($self) = @_;
	return $self->{DATA}{domain} || '';
}

# +
# +  --  
# +
sub registrar {
	my($self) = @_;
	
#          'registrar_whois_server' ,
#          'registrar_abuse_contact_phone' 
#          'registrar_iana_id' 
#          'registrar' 
#          'registrar_url' 
#          'registrar_registration_expiration_date' 
#          'registrar_abuse_contact_email' 

	if($self->{DATA}) {
		return sprintf("%s\n - - - - - - - - - - - - - - -\nurl: %s\nph: %s\nemail: %s\nabuse ph: %s\nabuse em: %s",
			$self->{DATA}{registrar} || '',
			$self->{DATA}{registrar_url} || '',
			$self->{DATA}{registrar_contact_phone} || '',
			$self->{DATA}{registart_contact_email} || '',
			$self->{DATA}{registrar_abuse_contact_phone} || '',
			$self->{DATA}{registrar_abuse_contact_email} || ''
		);
	}

	return '- unable to parse';
}

# +
# +  --  
# +
sub registrant {
	my($self) = @_;
	my $street_addr = '';

#          'registrant_fax' 
#          'registrant_country' 
#          'registrant_email' 
#          'registrant_phone' 
#          'please_note' 
#          'registrant_name' 
#          'registrant_organization' 
#          'registrant_city' 
#          'registrant_postal_code'
#          'registrant_street' => [

	return ' - unavailable ' unless $self->{DATA}{registrant_organization};

	if($self->{DATA}{registrant_street}){
		if(ref($self->{DATA}{registrant_street}) eq 'ARRAY'){
			$street_addr = join("\n",$self->{DATA}{registrant_street});
		}
		else {
			$street_addr = $self->{DATA}{registrant_street};
		}
	}

	return sprintf("%s\n - - - - - - - - - - - - - - -\n%s\n%s\n%s\nemail: %s\nph: %s\nfax: %s\nnote: %s",
		$self->{DATA}{registrant_organization},
		$self->{DATA}{registrant_name},
		$street_addr,
		sprintf('%s, %s',$self->{DATA}{registrant_city},$self->{DATA}{registrant_country}),
		$self->{DATA}{registrant_email},
		$self->{DATA}{registrant_phone},
		$self->{DATA}{registrant_fax},
		$self->{DATA}{please_note}
	);
}

# +
# +  --  
# +
sub blind_iterate {
	my ($ax) = @_;
	my @outlist;
	return @outlist unless ref($ax) eq 'ARRAY';

	my $ct=0;
	while (my $ar = pop($ax) || $ct < 20){
		#printf("%d %s\n",$ct++,$ar);
		if(ref($ar) eq 'ARRAY'){
			$ax = $ar;
			next;
		}
		push(@outlist,$ar) if length($ar) > 1;	
		last unless length($ar) > 1;	
	}

	return @outlist;
}

# +
# +  --  
# +
sub emails {
	my($self) = @_;

	return join("\n",blind_iterate($self->{DATA}{emails}));
}

# +
# +  --  
# +
sub nameservers {
	my($self) = @_;
	my @nslist;
	foreach my $rec (blind_iterate($self->{DATA}{nameservers})){
		push(@nslist,$rec->{domain}) if ref($rec) eq 'HASH';
	}

	return join("\n",@nslist); 
}

1;
