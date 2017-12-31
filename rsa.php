<?php
class rsa{
	private $public_key;
	private $private_key;
	/**
	 * 生成公私钥
	 * @return boolean
	 */
	public function create_key(){
		$config=array(
			'digest_alg'=>'sha1',
			'private_key_bits'=>1024,
			'private_key_type'=>OPENSSL_KEYTYPE_RSA
		);
		$res=openssl_pkey_new($config);
		if($res==false) return false;
		openssl_pkey_export($res,$private_key,null,$config);
		$public_key=openssl_pkey_get_details($res)["key"];
		$this->public_key=$public_key;
		$this->private_key=$private_key;
		return true;
	}
	/**
	 * 私钥加密
	 * @param $code [数据]
	 * @return string
	 */
	public function private_encrypt(string $code){
		openssl_private_encrypt($code,$output,$this->private_key);
		return base64_encode($output);
	}
	/**
	 *  私钥解密
	 * @param $code [公钥加密密文]
	 * @return string
	 */
	public function public_decrypt(string $code){
		openssl_public_decrypt(base64_decode($code),$output,$this->public_key);
		return $output;
	}
	/**
	 * 公钥加密
	 * @param $code [数据]
	 * @return string
	 */
	public function public_encrypt(string $code){
		openssl_public_encrypt($code,$output,$this->public_key);
		return base64_encode($output);
	}
	/**
	 * 公钥解密
	 * @param $code [私钥加密密文]
	 * @return string
	 */
	public function private_decrypt(string $code){
		openssl_private_decrypt(base64_decode($code),$output,$this->private_key);
		return $output;
	}
	/**
	 * 公钥/私钥格式化
	 * @param $key [公钥/私钥]
	 * @param $public [是否为公钥]
	 * @return string
	 */
	function format_key(string $key,bool $public=true){
		$pem=chunk_split($key,64,PHP_EOL);
		if($public) return '-----BEGIN PUBLIC KEY-----'.PHP_EOL.$pem.'-----END PUBLIC KEY-----';
		else return '-----BEGIN PRIVATE KEY-----'.PHP_EOL.$pem.'-----END PRIVATE KEY-----';
	}
}