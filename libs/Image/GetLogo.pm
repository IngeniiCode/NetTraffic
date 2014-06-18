# =============================
  package Image::GetLogo;
# =============================


# =============================
#  Define required modules
# =============================
use strict;
use LWP::Simple;
use Image::Size;
#use Image::Resize;
#use Image::Magick;
use Data::Dumper;

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
		'image_path' => @_,
		'image_x'    => 0,
		'image_y'    => 0,
	};
	
	return bless ($self, $class); #this is what makes a reference into an object
}

# +
# +  --  define a sub-routine 
# +
sub getImage {
	my ($self,$logourl) = @_;

	my @pathparts = split('/',$logourl);
	my $self->{fname} = sprintf('%s/%s',$self->{image_path},pop(@pathparts));

	# download image from interwebs
	getstore($logourl, $self->{fname});

	# get the image size
	($self->{image_x},$self->{image_y}) = imgsize($self->{fname});
	
	# resize the image save as our target size of 96x96
	return $self->{fname};
}

# +
# +  -- retrieve image X size
# +
sub resize {
	my ($self) = @_;

	$self->thumbfile = sprintf('%s.jpeg',$self->{fname});

	#open(FH,$self->thumbfile);
	#print FH $gd->jpeg();
	#close(FH);

	return $self->thumbfile;
}

# +
# +  -- retrieve image X size
# +
sub image_x {
	my ($self) = @_;
	return $self->image_x;
}

# +
# +  -- retrieve image X size
# +
sub image_y {
	my ($self) = @_;
	return $self->image_y;
}

# +
# +  -- retrieve image X size
# +
sub image_dims {
	my ($self) = @_;
	return {
		x => $self->image_x,
		y => $self->image_y,
	};
}



# +
# =============================
1;
