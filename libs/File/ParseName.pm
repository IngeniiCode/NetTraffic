# =============================
  package File::ParseName;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
use URI::Escape;
use Data::Dumper;

# =============================
#  Define global scoped variables
# =============================
my $fBase   = '';  # path to intake file, drop report in same location.

# =============================
#  Define  Package Methods
# =============================

# + + + + + + + + + + + + + + + + + + + +
# +  --   C O N S T R U C T O R     --  + 
# + + + + + + + + + + + + + + + + + + + +
sub new {
	my $class = shift;

	my $self = parseFileName(@_);
	
	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  app id parser 
# +
sub get_app_id {
	my($self) = @_;
	return $self->{appID}; 
}

# +
# +  --  image file output  
# +
sub path {
	my($self) = @_;
	
	return $self->{fpath}; 
}


# +
# +  --  id extractor
# +
sub decode_id {
	my($fbase) = @_;

	my @parts = split('\.',$fbase);
	my $apEnc = shift(@parts); # get first element
	return uri_unescape($apEnc);

}

# +
# +  -- filename hacking of parts 
# +
sub parseFileName {
	my($filename) = @_;

	my @parts = split('/',$filename); 
	my $fbase  = pop @parts; # get last element
	my $appID  = decode_id($fbase);

	return {
		fpath => join('/',@parts),
		parts => \@parts,
		fbase => $fbase,
		appID => $appID, 
	};

}

# +
# =============================
1;
