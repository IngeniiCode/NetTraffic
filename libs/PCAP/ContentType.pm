# =============================
  package Pcap::ContentType;
# =============================
use strict;
use Switch;

# =============================
#  Define required modules
# =============================

# =============================
#  Define  Package Variables
# =============================

# =============================
#  Define  Package Methods
# =============================

# +
# +  try to determine if this is media content
# +
sub is_media {
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
sub is_payload {
	my($type) = @_;

	# guess at content type if not defined --- this will need to be extended!!
	switch($type) {
		case { $_[0] =~  /json/i }   { return 1; }
		case { $_[0] =~  /xml/i }    { return 1; }
	};

	return;
}


1; 

