<?php
    class LanguageTranslator
    {
        private $url = 'https://www.googleapis.com/language/translate/v2';        
        protected $_apiKey;
 
        
        public function __construct($apiKey)
        {
            $this->_apiKey = $apiKey;
        }
 
        public function translate($data, $target, $source = '')
        {
            // this is the form data to be included with the request
            $values = array(
                'key'    => $this->_apiKey,
                'target' => $target,
                'q'      => $data
            );
 
            // only include the source data if it's been specified
            if (strlen($source) > 0) {
                $values['source'] = $source;
            }
 
            // turn the form data array into raw format so it can be used with cURL
            $formData = http_build_query($values);
 
            $ch = curl_init();
            
            $cOPT = array(
				CURLOPT_URL		   			=> $this->url,
				CURLOPT_RETURNTRANSFER	   	=> true,
				CURLOPT_POSTFIELDS			=> $formData,
				CURLOPT_HTTPHEADER			=> array('X-HTTP-Method-Override: GET')
			);
			
			curl_setopt_array($ch,$cOPT);

            $json = curl_exec($ch);
            curl_close($ch);
 
            // response data
            $data = json_decode($json, true);
             			
            // ensure the returned data is valid
            if (!is_array($data) || !array_key_exists('data', $data)) {
                throw new Exception('Unable to find data key');
            }
             
            if (!array_key_exists('translations', $data['data'])) {
                throw new Exception('Unable to find translations key');
            }
 
            if (!is_array($data['data']['translations'])) {
                throw new Exception('Expected array for translations');
            }
 			
 			//return single translation
           foreach ($data['data']['translations'] as $translation) {
                return $translation['translatedText'];
            }
 
            // throw exception if failed
            throw new Exception('Translation failed');
            
        }
    }
?>