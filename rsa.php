<?php
	define('keyLen',1024);  // 请根据需要自行修改密钥长度
	class RSA{
		/**
		 * 生成公私钥
		 * @return array|false
		 */
		public static function create_key(){
			$config=array(
				'config'=>dirname(__FILE__).'/openssl.cnf',
				'digest_alg'=>'sha256',
				'private_key_bits'=>keyLen,
				'private_key_type'=>OPENSSL_KEYTYPE_RSA
			);
			$res=openssl_pkey_new($config);
			if($res==false){
				echo(openssl_error_string());
				return false;
			}
			openssl_pkey_export($res,$private_key,null,$config);
			$public_key=openssl_pkey_get_details($res)["key"];
			return array($public_key,$private_key);
		}
		/**
		 * 加密
		 * @param $data [数据]
		 * @param $key [公钥/私钥]
		 * @param $public [是否为公钥]
		 * @return string
		 */
		public static function encode($data,$key,$public=true){
			$key=self::format_key($key,$public);
			$result=array();
			while(strlen($chunk=substr($data,0,keyLen/8-11))>0){
				$data=substr($data,strlen($chunk));
				if($public) $result[]=self::public_encrypt($chunk,$key);
				else $result[]=self::private_encrypt($chunk,$key);
				unset($chunk);
			}
			return implode('**&&**',$result);
		}
		/**
		 * 解密
		 * @param $data [密文]
		 * @param $key [公钥/私钥]
		 * @param $public [是否为公钥]
		 * @return string
		 */
		public static function decode($data,$key,$public=true){
			$key=self::format_key($key,$public);
			$result=array();
			foreach(explode('**&&**',$data) as $chunk){
				if($public) $result[]=self::public_decrypt($chunk,$key);
				else $result[]=self::private_decrypt($chunk,$key);
				unset($chunk);
			}
			return implode('',$result);
		}
		/**
		 * 公钥加密
		 * @param $code [数据]
		 * @param $key [公钥]
		 * @return string
		 */
		private static function public_encrypt($code,$key){
			openssl_public_encrypt($code,$output,$key,OPENSSL_PKCS1_PADDING);
			return base64_encode($output);
		}
		/**
		 * 公钥解密
		 * @param $code [密文]
		 * @param $key [公钥]
		 * @return string
		 */
		private static function public_decrypt($code,$key){
			openssl_public_decrypt(base64_decode($code),$output,$key,OPENSSL_PKCS1_PADDING);
			return $output;
		}
		/**
		 * 私钥加密
		 * @param $code [数据]
		 * @param $key [私钥]
		 * @return string
		 */
		private static function private_encrypt($code,$key){
			openssl_private_encrypt($code,$output,$key,OPENSSL_PKCS1_PADDING);
			return base64_encode($output);
		}
		/**
		 *  私钥解密
		 * @param $code [密文]
		 * @param $key [私钥]
		 * @return string
		 */
		private static function private_decrypt($code,$key){
			openssl_private_decrypt(base64_decode($code),$output,$key,OPENSSL_PKCS1_PADDING);
			return $output;
		}
		/**
		 * 格式化密钥
		 * @param $key [公钥/私钥]
		 * @param $public [是否为公钥]
		 * @return string
		 */
		private static function format_key($key,$public){
			if(stripos($key,'-----')!==false) return $key;
			$pem=chunk_split($key,64,PHP_EOL);
			if($public) return '-----BEGIN PUBLIC KEY-----'.PHP_EOL.$pem.'-----END PUBLIC KEY-----';
			else return '-----BEGIN PRIVATE KEY-----'.PHP_EOL.$pem.'-----END PRIVATE KEY-----';
		}
	}