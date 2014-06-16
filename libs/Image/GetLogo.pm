# =============================
  package Image::GetLogo;
# =============================


# =============================
#  Define required modules
# =============================
use strict;
use Data::Dumper;
use LWP::Simple;

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
	my $class = shift;
	my $self  = { 
		'image_path' => @_ 
	};
	
	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  define a sub-routine 
# +
sub getImage {
	my($self,$logourl) = @_;

	my @pathparts = split('/',$logourl);
	my $fname = sprintf('%s/%s',$self->{image_path},pop(@pathparts));

	# download image from interwebs
	getstore($logourl, $fname);

	return $fname;

}

# +
# =============================
1;
