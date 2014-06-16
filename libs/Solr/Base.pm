# =============================
  package Solr::Base;
# =============================

# =============================
#  Define required modules
# =============================
use strict;
use LWP::Simple;
use Data::Dumper;
use URI::Escape;
use Encode qw(decode encode);
use JSON qw( decode_json );  # From CPAN

# =============================
#  Define global scoped variables
# =============================
my $fBase   = '';  # path to intake file, drop report in same location.
my $CORES   = {
	'CORE1' =>      'http://solrcluster-1910154206.us-east-1.elb.amazonaws.com/solr/app_searchb',
	'CORE2' =>      'http://solrcluster-1910154206.us-east-1.elb.amazonaws.com/solr/3p_app_search',
	'CORE3' =>      'http://solrcluster-1910154206.us-east-1.elb.amazonaws.com/solr/3p_app_searchb',
	'CORE4' =>      'http://ec2-54-198-109-204.compute-1.amazonaws.com:8983/solr/app_searchb',
	'CORE-REV' =>   'http://solrcluster-1910154206.us-east-1.elb.amazonaws.com/solr/app_reviews',
};

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
sub getApp {
	my($self,$appID) = @_;

	my $url = $self->solrUrlSynth($appID);

	my $content = get($url) or die 'Unable to get page';
	my $package = decode_json(encode('UTF-8',$content));

	#  find the parts that I want.
	if (my $obj = shift($package->{response}{docs})){
		my $info = {	
			id          => $obj->{id} || 0,
			logo        => $obj->{appLogo} || '',
			title       => $obj->{appTitle} || '',
			description => $obj->{appDescription} || '',
			developer   => $obj->{developer} || '',
		};

		return $info;
	}

	return {
		logo => 'nothing',
		title => 'app not found',
		description => 'app not found',
	};
}

# +
# +  --  define a sub-routine 
# +
# +  http://solrcluster-1910154206.us-east-1.elb.amazonaws.com/solr/app_searchb/select?q=id%3A%22iB9gEvZWc6xqpZWJtQnMQg%22&fl=id%2CappTitle%2CappDescription%2CappLogo&wt=json&indent=true
# +
sub solrUrlSynth {
	my($self,$appID) = @_;

	my $base = '/select?q=id%3A%22'.uri_escape($appID).'%22&fl=id%2CappTitle%2CappDescription%2CappLogo%2Cdeveloper&wt=json&indent=true';

	return $CORES->{CORE1}.$base;
}

# +
# =============================
1;

 __END__

