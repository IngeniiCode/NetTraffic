# =============================
  package Pcap::DecodeJson;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
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
	};

        return bless ($self, $class); #this is what makes a reference into an object
}

1;
