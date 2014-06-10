#!/usr/bin/perl

use URI::Encode qw ( uri_encode uri_decode );
use WWW::Mechanize;
use JSON qw( decode_json );
use Data::Dumper;

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
#  MECHANIZE
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
my $M = WWW::Mechanize->new();
$M->agent_alias( 'Windows IE 6' );  #  really fake browser agent
my $appid = '';

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
# +  Grab the latest appID from the main translation page:
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
if($M->get('http://www.bing.com/translator')){
	my $response = $M->content();
	foreach my $line (split /[\n\r]/,$response){
		if ($line =~  /^Default.Constants.AjaxApiAppId.+'(.*)'/){
			$appid = $1;
			last;   # done.. quit trying
		}
	}
}

printf("AppID Key: %s\n",$appid);

my $string = '高考化学宝典是Rainning Studio打造的一款辅助高中生学习和备考化学重量级App，包含了高考所有知识点；高考化学宝典包含了知识点外的实验大全，模型解题，解题方法与技巧，是化学门类通用的秒杀高中化学学习，甚至高考化学的利器！让用户不只是查看，还可以进行有效的训练，充分掌握高考的所有知识点、解题方法和解题技巧。让您体验到速度与翔实，艺术与实用的完美统一。*本工作室团队成员曾经面对高考也有很多困惑，总结团队成员和高考成功者的笔记，梳理了所有可能考到的知识点的，Rainning Studio承若，此App会以最快的速度更新最新咨询和考点！';

my $str_temp = 'http://api.microsofttranslator.com/v2/ajax.svc/TranslateArray2?appId=%%22%s%%22&texts=[%%22%s%%22]&from=%%22zh-cht%%22&to=%%22en%%22&oncomplete=_mstc5&onerror=_mste5&loc=en&ctr=&rgp=181969f1';

my $str3 = sprintf($str_temp,$appid,uri_encode($string));

printf("POST: %s\n",$str3);

# Setup the headers
$M->add_header( 'Referer' => 'http://www.bing.com/translator');
printf("\n===== ORIGINAL ======\n%s\n",$string);

if($M->get($str3)){
	my $response = $M->content();

	$response =~ s/^.*_mst[a-z]\d+\(//g;
	$response =~ s/\);?$//g;

	printf("\n===== STRIPPED ======\n%s\n",$response);

	my $data = decode_json $response; 
	printf("\n===== TRANSLATE PAYLOAD ======\n%s\n",Dumper $data);
}

#
#   Example error for an expired AppID key:



#   Example AppIDs:
#	appId=%22TVyAzrlurstNkKPw01yh7hpnibGjYPMpINXy3MnLYdT0*%22
#
#   AppID is found in a JavaScript block in the page   here is an example:
#	Default.Constants.AjaxApiAppId = 'THrgMkYvHdLlVtdk3tUxBPp0eaP45SMYQYdVs437D-uA*';   <-- ID changes on EVERY page load
#	Default.Constants.AjaxApiAppId = 'THeGeTLnE3iK1CnEqIej15OVu-aYsVmadGcgjL79CLzw*';   <-- ID changes on EVERY page load
#
#   -- parsing this ID before sending the translation requests might be all that's needed!!

exit;
