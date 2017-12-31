<?php
class rsa{
	// 公钥
	private $public_key='';
	// 私钥
	private $private_key='';
	// 公密钥资源
	private $public_key_resource='';
	// 私密钥资源
	private $private_key_resource='';
	/**
	 * 架构函数
	 * @param [string] $public_key_file  [公密钥文件地址]
	 * @param [string] $private_key_file [私密钥文件地址]
	 */
	public function __construct($public_key_file,$private_key_file){
		try{
			if(!file_exists($public_key_file) || !file_exists($private_key_file)) throw new Exception('key file no exists');
			if(false==($this->public_key=file_get_contents($public_key_file)) || false==($this->private_key=file_get_contents($private_key_file))) throw new Exception('read key file fail');
			if(!($this->public_key_resource=openssl_pkey_get_public($this->public_key)) or !($this->private_key_resource=openssl_pkey_get_private($this->private_key))) throw new Exception('public key or private key no usable');
		}catch(Exception $e){
			exit($e->getMessage());
		}
	}
	/**
	 * 生成公私钥
	 * @return array|false
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
		$public_key=openssl_pkey_get_details($res);
		return array('public_key'=>$public_key["key"],'private_key'=>$private_key);
	}
	/**
	 * 私钥加密
	 * @param $code [数据]
	 * @return string
	 */
	public function private_encrypt(string $code){
		openssl_private_encrypt($code,$output,$this->private_key_resource);
		return base64_encode($output);
	}
	/**
	 *  私钥解密
	 * @param $code [公钥加密密文]
	 * @return string
	 */
	public function public_decrypt(string $code){
		openssl_public_decrypt(base64_decode($code),$output,$this->public_key_resource);
		return $output;
	}
	/**
	 * 公钥加密
	 * @param $code [数据]
	 * @return string
	 */
	public function public_encrypt(string $code){
		openssl_public_encrypt($code,$output,$this->public_key_resource);
		return base64_encode($output);
	}
	/**
	 * 公钥解密
	 * @param $code [私钥加密密文]
	 * @return string
	 */
	public function private_decrypt(string $code){
		openssl_private_decrypt(base64_decode($code),$output,$this->private_key_resource);
		return $output;
	}
}