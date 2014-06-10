# =============================
  package File::ParseName;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
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
	my $self  = { @_ };
	
	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  define a sub-routine 
# +
sub routine {
	my($type,$header,$raw) = @_;

	return;
}

# +
# =============================
1;
