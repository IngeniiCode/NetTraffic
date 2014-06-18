# =============================
  package Reporter::Formats;
# =============================

use strict;
# - - - - - - - - - - - - - - - 

sub set_formatting {
	my ($WB) = @_;

	my $fmt = {};
 
	# 
	#  Define format palet
	#
	my $bg_colors = {
		'banner'         => $WB->set_custom_color( 27, 182, 1, 35 ),
		'info_head_dk'   => $WB->set_custom_color( 41, 64, 64, 64 ), 
		'info_head_lt'   => 'white',
		'info_label'     => 'white', 
		'info_app_title' => 'white',
		'info_lage'      => 'white',
		'section_head'   => $WB->set_custom_color( 42, 89, 89, 89 ),
		'group_head'     => $WB->set_custom_color( 43, 128, 128, 128 ),
		'col_head'       => 'white',
		'conversation'   => $WB->set_custom_color( 44, 218, 218, 218 ),
	};
	my $fg_colors = {
		'banner'         => 'white',
		'info_head_dk'   => $bg_colors->{info_head_lt},
		'info_head_lt'   => $bg_colors->{info_head_dk},
		'info_label'     => $bg_colors->{info_head_dk},
		'info_app_title' => $bg_colors->{info_head_dk},
		'info_large'     => $bg_colors->{info_head_dk},
		'section_head'   => 'white',
		'group_head'     => 'white',
		'col_head'       => $bg_colors->{info_head_dk},
		'conversation'   => $bg_colors->{info_head_dk},
	};

	#
	#  Define the formats
	#
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
		$fmt->{info_label}->set_align( 'right' );
		$fmt->{info_label}->set_align( 'top' );
		$fmt->{info_label}->set_right( 2 );
		$fmt->{info_label}->set_border_color( $bg_colors->{info_head_dk} );	
	
	$fmt->{info_app_title} = $WB->add_format( bold => 1 );
		$fmt->{info_app_title}->set_size( 14 );
		$fmt->{info_app_title}->set_color( $fg_colors->{info_app_title} );
		$fmt->{info_app_title}->set_align( 'left' );
		$fmt->{info_app_title}->set_align( 'top' );

	$fmt->{info_large} = $WB->add_format( bold => 0 );
		$fmt->{info_large}->set_size( 14 );
		$fmt->{info_large}->set_color( $fg_colors->{info_large} );
		$fmt->{info_large}->set_align( 'left' );
		$fmt->{info_large}->set_align( 'top' );

	$fmt->{info_desc} = $WB->add_format( bold => 0 );
		$fmt->{info_desc}->set_size( 12 );
		$fmt->{info_desc}->set_color( $fg_colors->{info_desc} );
		$fmt->{info_desc}->set_align( 'left' );
		$fmt->{info_desc}->set_align( 'top' );
		$fmt->{info_desc}->set_text_wrap( 1 );
	
	$fmt->{section_head} = $WB->add_format( bold => 1 );
		$fmt->{section_head}->set_size( 16 );
		$fmt->{section_head}->set_color( $fg_colors->{section_head} );
		$fmt->{section_head}->set_bg_color( $bg_colors->{section_head} );
		$fmt->{section_head}->set_align( 'center_across' );
		$fmt->{section_head}->set_align( 'vcenter' );
		$fmt->{section_head}->set_border(2);
		$fmt->{section_head}->set_border_color( $bg_colors->{section_head} );

	$fmt->{group_head} = $WB->add_format( bold => 1 );
		$fmt->{group_head}->set_size( 13 );
		$fmt->{group_head}->set_color( $fg_colors->{group_head} );
		$fmt->{group_head}->set_bg_color( $bg_colors->{group_head} );
		$fmt->{group_head}->set_align( 'left' );
		$fmt->{group_head}->set_align( 'top' );

	$fmt->{col_head} = $WB->add_format( bold => 1 );
		$fmt->{col_head}->set_size( 11 );
		$fmt->{col_head}->set_color( $fg_colors->{col_head} );
		$fmt->{col_head}->set_align( 'left' );
		$fmt->{col_head}->set_align( 'bottom' );

	$fmt->{normal} = $WB->add_format( bold => 0 );
		$fmt->{normal}->set_size( 11 );
		$fmt->{normal}->set_color( $fg_colors->{normal} );
		$fmt->{normal}->set_align( 'left' );
		$fmt->{normal}->set_align( 'top' );

	$fmt->{conversation} = $WB->add_format( bold => 1);
		$fmt->{conversation}->set_size( 12 );
		$fmt->{conversation}->set_color( $fg_colors->{conversation} );
		$fmt->{conversation}->set_bg_color( $bg_colors->{conversation} );
		$fmt->{conversation}->set_top( 2 );
	$fmt->{conversation_index} = $WB->add_format( bold => 1, align => 'center', valign => 'top');
		$fmt->{conversation_index}->set_top( 2 );
		$fmt->{conversation_index}->set_left( 2 );
	$fmt->{conversation_footer} = $WB->add_format( bold => 1);
		$fmt->{conversation_footer}->set_top( 2 );
	$fmt->{conversation_right_frame} = $WB->add_format( bold => 1, align => 'right', valign => 'top');
		$fmt->{conversation_right_frame}->set_top( 2 );
		$fmt->{conversation_right_frame}->set_right( 2 );

	$fmt->{whois} = $WB->add_format( bold => 0, align => 'left', valign => 'top');
		$fmt->{whois}->set_text_wrap();

	$fmt->{wrap}   = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
	$fmt->{wrap_c} = $WB->add_format( text_wrap => 1, align => 'left', valign => 'top');
		$fmt->{wrap_c}->set_align( 'vjustify' );

	return $fmt;
}

# =============================
1;
