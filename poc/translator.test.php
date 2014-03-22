<?php
    require_once('translate.class.php');
 
    $apiKey = 'AIzaSyBHE144gEpilPj_8jXEug3Ci5JuBfl6npE';
 
    $source = 'zh-CN';
 
    $target = 'en';
    $sourceData = "愤怒的小鸟(中文版)";
 
    $translator = new LanguageTranslator($apiKey);
 
    $targetData = $translator->translate($sourceData, $target, $source);
    printf($targetData);
    
?>