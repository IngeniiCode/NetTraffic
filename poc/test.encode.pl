#!/usr/bin/perl

use utf8;
use Text::Unidecode;
my $string = '高考化学宝典是Rainning Studio打造的一款辅助高中生学习和备考化学重量级App，包含了高考所有知识点；高考化学宝典包含了知识点外的实验大全，模型解题，解题方法与技巧，是化学门类通用的秒杀高中化学学习，甚至高考化学的利器！让用户不只是查看，还可以进行有效的训练，充分掌握高考的所有知识点、解题方法和解题技巧。让您体验到速度与翔实，艺术与实用的完美统一。*本工作室团队成员曾经面对高考也有很多困惑，总结团队成员和高考成功者的笔记，梳理了所有可能考到的知识点的，Rainning Studio承若，此App会以最快的速度更新最新咨询和考点！';
print unidecode($string); # This year I went to Bei Jing  Perl workshop.

exit;
