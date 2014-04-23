# =============================
  package Pcap::DecodeJson;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
use JSON qw(decode_json);
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
        my ($class,$raw) = @_;
	my $self = {
		'raw' => $raw,  # store the raw data.
	};

        return bless ($self, $class); #this is what makes a reference into an object
}


# +
# +  Decode
# + 
sub extract {
	my($self) = @_;

	my $decoded;
	my $obj;
	my @urls   = ();
	my @emails = ();
	

	$Data::Dumper::Terse = 1;        # don't output names where feasible
	#  attempt to decode, if that fails keep trying to normalize until there is nothing left to parse
	eval {
		my $str = $self->{raw};
		chomp($str);
		return '' unless $str;
		$str =~ s/^.*\{/\{/m;  # try to strip off any preceeding crap
		$str =~ s/\}\];?$/\}/; # try to strip off the tailing backet if found
		if(my $obj = decode_json $str){
			$decoded = sprintf("%s",Dumper($obj));
		}
	};
	warn $@ if $@;

	if(ref($obj) eq 'HASH') {
			

	}

	return {
		readable => $decoded,
	} 
}

1;
