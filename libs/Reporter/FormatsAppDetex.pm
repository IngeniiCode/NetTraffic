# =============================
  package Reporter::Formats;
# =============================

use strict;
# - - - - - - - - - - - - - - - 

sub set_formatting {
	my ($WB) = @_;

	my $fmt = {};
 
	# Define WorkBook formatting
	my $bg_colors = {
		'banner'         => $WB->set_custom_color( 27, 182, 1, 35 ),
		'info_head_dk'   => $WB->set_custom_color( 41, 64, 64, 64 ), 
		'info_head_lt'   => 'white',
		'info_label'     => 'white', 
		'info_app_title' => 'white',
		'info_lage'      => 'white',
	};
	my $fg_colors = {
		'banner'         => 'white',
		'info_head_dk'   => $bg_colors->{info_head_lt},
		'info_head_lt'   => $bg_colors->{info_head_dk},
		'info_label'     => $bg_colors->{info_head_dk},
		'info_app_title' => $bg_colors->{info_head_dk},
		'info_large'     => $bg_colors->{info_head_dk},
	};


#	my $lt_grey = $WB->set_custom_color( 40, 236, 236, 236 );
#	my $headred = $WB->set_custom_color( 27, 182, 1, 35 );
#	my $blkgray = $WB->set_custom_color( 38, 64, 64, 64 );
#	my $cl_section = $WB->set_custom_color( 33, 84, 84, 84 );

	$fmt->{banner} = $WB->add_format( bold => 1 );
		$fmt->{banner}->set_size( 20 );
		$fmt->{banner}->set_color( $fg_colors->{banner} );
		$fmt->{banner}->set_bg_color( $bg_colors->{banner} );
		$fmt->{banner}->set_align( 'center_across' );
		$fmt->{banner}->set_align( 'vcenter' );

	$fmt->{info_head_dk} = $WB->add_format( bold => 1 );
		$fmt->{info_head_dk}->set_size( 16 );
		$fmt->{info_head_dk}->set_color( $fg_colors->{info_head_dk} );
		$fmt->{info_head_dk}->set_bg_color( $bg_colors->{info_head_dk} );
		$fmt->{info_head_dk}->set_align( 'center_across' );
		$fmt->{info_head_dk}->set_align( 'vcenter' );
		$fmt->{info_head_dk}->set_border(2);	
		$fmt->{info_head_dk}->set_border_color( $bg_colors->{info_head_dk} );	

	$fmt->{info_head_lt} = $WB->add_format( bold => 1 );
		$fmt->{info_head_lt}->set_size( 16 );
		$fmt->{info_head_lt}->set_color( $fg_colors->{info_head_lt} );
		$fmt->{info_head_lt}->set_bg_color( $bg_colors->{info_head_lt} );
		$fmt->{info_head_lt}->set_align( 'left' );
		$fmt->{info_head_lt}->set_align( 'vcenter' );
		$fmt->{info_head_lt}->set_border(2);	
		$fmt->{info_head_lt}->set_border_color( $bg_colors->{info_head_dk} );

	$fmt->{info_label} = $WB->add_format( bold => 0 );
		$fmt->{info_label}->set_size( 14 );
		$fmt->{info_label}->set_color( $fg_colors->{info_label} );
		#$fmt->{info_label}->set_bg_color( $bg_colors->{info_label} );
		$fmt->{info_label}->set_align( 'right' );
		$fmt->{info_label}->set_align( 'top' );
		$fmt->{info_label}->set_right( 2 );
		$fmt->{info_label}->set_border_color( $bg_colors->{info_head_dk} );	
	
	$fmt->{info_app_title} = $WB->add_format( bold => 1 );
		$fmt->{info_app_title}->set_size( 14 );
		$fmt->{info_app_title}->set_color( $fg_colors->{info_app_title} );
		#$fmt->{info_app_title}->set_bg_color( $bg_colors->{info_app_title} );
		$fmt->{info_app_title}->set_align( 'left' );
		$fmt->{info_app_title}->set_align( 'top' );

	$fmt->{info_large} = $WB->add_format( bold => 0 );
		$fmt->{info_large}->set_size( 14 );
		$fmt->{info_large}->set_color( $fg_colors->{info_large} );
		#$fmt->{info_large}->set_bg_color( $bg_colors->{info_large} );
		$fmt->{info_large}->set_align( 'left' );
		$fmt->{info_large}->set_align( 'top' );

	$fmt->{info_desc} = $WB->add_format( bold => 0 );
		$fmt->{info_desc}->set_size( 12 );
		$fmt->{info_desc}->set_color( $fg_colors->{info_desc} );
		#$fmt->{info_desc}->set_bg_color( $bg_colors->{info_desc} );
		$fmt->{info_desc}->set_align( 'left' );
		$fmt->{info_desc}->set_align( 'top' );
		$fmt->{info_desc}->set_text_wrap( 1 );
	
	return $fmt;
}

# =============================
1;
