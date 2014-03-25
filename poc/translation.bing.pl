#!/usr/bin/perl

use WWW::Mechanize;
use JSON qw( decode_json );
use Data::Dumper;

my $string = '高考化学宝典是Rainning Studio打造的一款辅助高中生学习和备考化学重量级App，包含了高考所有知识点；高考化学宝典包含了知识点外的实验大全，模型解题，解题方法与技巧，是化学门类通用的秒杀高中化学学习，甚至高考化学的利器！让用户不只是查看，还可以进行有效的训练，充分掌握高考的所有知识点、解题方法和解题技巧。让您体验到速度与翔实，艺术与实用的完美统一。*本工作室团队成员曾经面对高考也有很多困惑，总结团队成员和高考成功者的笔记，梳理了所有可能考到的知识点的，Rainning Studio承若，此App会以最快的速度更新最新咨询和考点！';

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 
#  MECHANIZE
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 

my $M = WWW::Mechanize->new();
$M->agent_alias( 'Windows IE 6' );  #  really fake browser agent

my $str1 = 'http://api.microsofttranslator.com/v2/ajax.svc/TranslateArray2?appId=%22TVyAzrlurstNkKPw01yh7hpnibGjYPMpINXy3MnLYdT0*%22&texts=[%22%E9%AB%98%E8%80%83%E5%8C%96%E5%AD%A6%E5%AE%9D%E5%85%B8%E6%98%AFRainning+Studio%E6%89%93%E9%80%A0%E7%9A%84%E4%B8%80%E6%AC%BE%E8%BE%85%E5%8A%A9%E9%AB%98%E4%B8%AD%E7%94%9F%E5%AD%A6%E4%B9%A0%E5%92%8C%E5%A4%87%E8%80%83%E5%8C%96%E5%AD%A6%E9%87%8D%E9%87%8F%E7%BA%A7App%EF%BC%8C%E5%8C%85%E5%90%AB%E4%BA%86%E9%AB%98%E8%80%83%E6%89%80%E6%9C%89%E7%9F%A5%E8%AF%86%E7%82%B9%EF%BC%9B%E9%AB%98%E8%80%83%E5%8C%96%E5%AD%A6%E5%AE%9D%E5%85%B8%E5%8C%85%E5%90%AB%E4%BA%86%E7%9F%A5%E8%AF%86%E7%82%B9%E5%A4%96%E7%9A%84%E5%AE%9E%E9%AA%8C%E5%A4%A7%E5%85%A8%EF%BC%8C%E6%A8%A1%E5%9E%8B%E8%A7%A3%E9%A2%98%EF%BC%8C%E8%A7%A3%E9%A2%98%E6%96%B9%E6%B3%95%E4%B8%8E%E6%8A%80%E5%B7%A7%EF%BC%8C%E6%98%AF%E5%8C%96%E5%AD%A6%E9%97%A8%E7%B1%BB%E9%80%9A%E7%94%A8%E7%9A%84%E7%A7%92%E6%9D%80%E9%AB%98%E4%B8%AD%E5%8C%96%E5%AD%A6%E5%AD%A6%E4%B9%A0%EF%BC%8C%E7%94%9A%E8%87%B3%E9%AB%98%E8%80%83%E5%8C%96%E5%AD%A6%E7%9A%84%E5%88%A9%E5%99%A8%EF%BC%81%E8%AE%A9%E7%94%A8%E6%88%B7%E4%B8%8D%E5%8F%AA%E6%98%AF%E6%9F%A5%E7%9C%8B%EF%BC%8C%E8%BF%98%E5%8F%AF%E4%BB%A5%E8%BF%9B%E8%A1%8C%E6%9C%89%E6%95%88%E7%9A%84%E8%AE%AD%E7%BB%83%EF%BC%8C%E5%85%85%E5%88%86%E6%8E%8C%E6%8F%A1%E9%AB%98%E8%80%83%E7%9A%84%E6%89%80%E6%9C%89%E7%9F%A5%E8%AF%86%E7%82%B9\u3001%E8%A7%A3%E9%A2%98%E6%96%B9%E6%B3%95%E5%92%8C%E8%A7%A3%E9%A2%98%E6%8A%80%E5%B7%A7\u3002%E8%AE%A9%E6%82%A8%E4%BD%93%E9%AA%8C%E5%88%B0%E9%80%9F%E5%BA%A6%E4%B8%8E%E7%BF%94%E5%AE%9E%EF%BC%8C%E8%89%BA%E6%9C%AF%E4%B8%8E%E5%AE%9E%E7%94%A8%E7%9A%84%E5%AE%8C%E7%BE%8E%E7%BB%9F%E4%B8%80\u3002*%E6%9C%AC%E5%B7%A5%E4%BD%9C%E5%AE%A4%E5%9B%A2%E9%98%9F%E6%88%90%E5%91%98%E6%9B%BE%E7%BB%8F%E9%9D%A2%E5%AF%B9%E9%AB%98%E8%80%83%E4%B9%9F%E6%9C%89%E5%BE%88%E5%A4%9A%E5%9B%B0%E6%83%91%EF%BC%8C%E6%80%BB%E7%BB%93%E5%9B%A2%E9%98%9F%E6%88%90%E5%91%98%E5%92%8C%E9%AB%98%E8%80%83%E6%88%90%E5%8A%9F%E8%80%85%E7%9A%84%E7%AC%94%E8%AE%B0%EF%BC%8C%E6%A2%B3%E7%90%86%E4%BA%86%E6%89%80%E6%9C%89%E5%8F%AF%E8%83%BD%E8%80%83%E5%88%B0%E7%9A%84%E7%9F%A5%E8%AF%86%E7%82%B9%E7%9A%84%EF%BC%8CRainning+Studio%E6%89%BF%E8%8B%A5%EF%BC%8C%E6%AD%A4App%E4%BC%9A%E4%BB%A5%E6%9C%80%E5%BF%AB%E7%9A%84%E9%80%9F%E5%BA%A6%E6%9B%B4%E6%96%B0%E6%9C%80%E6%96%B0%E5%92%A8%E8%AF%A2%E5%92%8C%E8%80%83%E7%82%B9%EF%BC%81%22]&from=%22zh-cht%22&to=%22en%22&oncomplete=_mstc5&onerror=_mste5&loc=en&ctr=&rgp=181969f1';

# Setup the headers
$M->add_header( 'Referer' => 'http://www.bing.com/translator');
printf("\n===== ORIGINAL ======\n%s\n",$string);

if($M->get($str1)){
	my $response = $M->content();

	$response =~ s/^.*_mstc\d+\(//g;
	$response =~ s/\);?$//g;

	#printf("\n===== STRIPPED ======\n%s\n",$response);


	my $data = decode_json $response; 
	printf("\n===== TRANSLATE PAYLOAD ======\n%s\n",Dumper $data);
}

exit;
