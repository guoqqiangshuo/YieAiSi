<?php
header('Content-Type: text/html; charset=utf-8');
/**
 * AES对称加密算法完整实例
 * User: yeaiming
 * Date: 2017/6/14
 * Time: 16:16
 */

class AESUtils {
    private $key;

    public function __construct()
	{
        $this->key = 'oO1dQboYRb5zTxBWpZcz3w==';
    }
    /**
     * This was AES-128 / CBC / PKCS5Padding
     * return base64_encode string
     * @author Terry
     * @param string $plaintext
     * @return string
     */
    public function encrypt($plaintext)
    {
        $plaintext = trim($plaintext);
        if ($plaintext == '') return '';
        $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);

        //PKCS5Padding
        $padding = $size - strlen($plaintext) % $size;
        // 添加Padding
        $plaintext .= str_repeat(chr($padding), $padding);


        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $key=self::substr($this->key, 0, mcrypt_enc_get_key_size($module));
        $iv = str_repeat("\0", $size);      //此处蛋碎一地啊，java里面的16个空数组对应的是\0.由于不懂java，这个地方百度了很久，后来是请教主管才搞定的。
        /* Intialize encryption */
        mcrypt_generic_init($module, $key, $iv);

        /* Encrypt data */
        $encrypted = mcrypt_generic($module, $plaintext);

        /* Terminate encryption handler */
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);
        return base64_encode($encrypted);
    }
    /**
     * Returns the length of the given string.
     * If available uses the multibyte string function mb_strlen.
     * @param string $string the string being measured for length
     * @return integer the length of the string
     */
    private function strlen($string)
    {
        return extension_loaded('mbstring') ? mb_strlen($string,'8bit') : strlen($string);
    }

    /**
     * Returns the portion of string specified by the start and length parameters.
     * If available uses the multibyte string function mb_substr
     * @param string $string the input string. Must be one character or longer.
     * @param integer $start the starting position
     * @param integer $length the desired portion length
     * @return string the extracted part of string, or FALSE on failure or an empty string.
     */
    private function substr($string,$start,$length)
    {
        return extension_loaded('mbstring') ? mb_substr($string,$start,$length,'8bit') : substr($string,$start,$length);
    }
    /**
     * This was AES-128 / CBC / PKCS5Padding
     * @author Terry
     * @param string $encrypted     base64_encode encrypted string
     * @throws CException
     * @return string
     */
    public function decrypt($encrypted)
    {
        if ($encrypted == '') return '';
        $ciphertext_dec = base64_decode($encrypted);
        $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
        $key=self::substr($this->key, 0, mcrypt_enc_get_key_size($module));

        $iv = str_repeat("\0", 16);    //解密的初始化向量要和加密时一样。
        /* Initialize encryption module for decryption */
        mcrypt_generic_init($module, $key, $iv);

        /* Decrypt encrypted string */
        $decrypted = mdecrypt_generic($module, $ciphertext_dec);

        /* Terminate decryption handle and close module */
        mcrypt_generic_deinit($module);
        mcrypt_module_close($module);
        $a = rtrim($decrypted,"\0");


        return rtrim($decrypted,"\0");
    }

}

$encryption = new AESUtils();
echo '加密：'.$encryption->encrypt('110108199002213312') . "<br/>";
echo '解密：'.$encryption->decrypt('0bwOHBSPMlUwbMGKEv6kDAqGAJ6niTUVznzULH+UF0s=');
echo "<hr/>";
