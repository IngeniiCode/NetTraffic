# =============================
  package Reporter::Formats;
# =============================

use strict;
# - - - - - - - - - - - - - - - 

sub set_formatting {
	my ($WB) = @_;

	my $fmt = {};
 
	# Define WorkBook formatting
	my $lt_grey = $WB->set_custom_color( 40, 236, 236, 236 );
	my $headred = $WB->set_custom_color( 27, 182, 1, 35 );
	my $blkgray = $WB->set_custom_color( 38, 64, 64, 64 );
	my $cl_section = $WB->set_custom_color( 33, 84, 84, 84 );

	$fmt->{header} = $WB->add_format( bold => 1);
		$fmt->{header}->set_size( 20 );
		$fmt->{header}->set_color( 'white' );
		$fmt->{header}->set_bg_color( $headred );

	$fmt->{app_title} = $WB->add_format( bold => 1);
		$fmt->{app_title}->set_size( 20 );
		$fmt->{app_title}->set_color( 'black' );
		$fmt->{app_title}->set_bg_color( 'white' );
		$fmt->{app_title}->set_top( 2 );
		$fmt->{app_title}->set_right( 2 );

	$fmt->{app_author} = $WB->add_format( bold => 1);
		$fmt->{app_author}->set_size( 20 );
		$fmt->{app_author}->set_color( 'black' );
		$fmt->{app_author}->set_bg_color( 'white' );
		$fmt->{app_author}->set_right( 2 );

	$fmt->{app_description} = $WB->add_format( bold => 0);
		$fmt->{app_description}->set_size( 13 );
		$fmt->{app_description}->set_text_wrap( 1 );
		$fmt->{app_description}->set_align( 'vjustify' );
		$fmt->{app_description}->set_align( 'top' );
		$fmt->{app_description}->set_color( 'black' );
		$fmt->{app_description}->set_bg_color( 'white' );
		$fmt->{app_description}->set_right( 2 );
		$fmt->{app_description}->set_bottom( 2 );

	$fmt->{app_logo} = $WB->add_format( bold => 0);
		$fmt->{app_logo}->set_text_wrap( 1 );
		$fmt->{app_logo}->set_align( 'vcenter' );
		$fmt->{app_logo}->set_top( 2 );
		$fmt->{app_logo}->set_left( 2 );
		$fmt->{app_logo}->set_right( 2 );
		$fmt->{app_logo}->set_bottom( 2 );
		#$fmt->{app_logo}->set_center_across( 1 );

	$fmt->{section} = $WB->add_format( bold => 1);
		$fmt->{section}->set_size( 16);
		$fmt->{section}->set_color( 'white' );
		$fmt->{section}->set_bg_color( 'blue' );
		
	$fmt->{sub_sect} = $WB->add_format( bold => 1);
		$fmt->{sub_sect}->set_size( 13 );
		$fmt->{sub_sect}->set_color( 'white' );
		$fmt->{sub_sect}->set_bg_color( 23 );

	$fmt->{conversation} = $WB->add_format( bold => 1);
		$fmt->{conversation}->set_size( 12 );
		$fmt->{conversation}->set_color( 'black' );
		$fmt->{conversation}->set_bg_color( $lt_grey );
		$fmt->{conversation}->set_top( 2 );
	$fmt->{conversation_index} = $WB->add_format( bold => 1, align => 'center', valign => 'top');
		$fmt->{conversation_index}->set_top( 2 );
		$fmt->{conversation_index}->set_left( 2 );
	$fmt->{conversation_footer} = $WB->add_format( bold => 1);
		$fmt->{conversation_footer}->set_top( 2 );
	$fmt->{conversation_right_frame} = $WB->add_format( bold => 1, align => 'right', valign => 'top');
		$fmt->{conversation_right_frame}->set_top( 2 );
		$fmt->{conversation_right_frame}->set_right( 2 );

	$fmt->{title_lt} = $WB->add_format( bold => 0);
		$fmt->{title_lt}->set_color( 'gray' );

	$fmt->{whois} = $WB->add_format( bold => 0, align => 'left', valign => 'top');
		$fmt->{whois}->set_text_wrap();

	$fmt->{title}  = $WB->add_format( bold => 1);

	$fmt->{bold}   = $WB->add_format( bold => 1);

	$fmt->{normal} = $WB->add_format( bold => 0, align => 'left', valign => 'top');

	$fmt->{wrap}   = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
	$fmt->{wrap_c} = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
		$fmt->{wrap_c}->set_align('vjustify');
	
	return $fmt;
}

# =============================
1;
