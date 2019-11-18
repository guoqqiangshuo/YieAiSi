<?php
header('Content-Type: text/html; charset=utf-8');
/**
 * RSA非对称加密算法完整实例
 * User: yeaiming
 * Date: 2017/6/14
 * Time: 18:45
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAje85EY7P95css31DW+tBMMmy
8MwZUcWncDVH1sSFy2PKF454R0nw8KcBeCAy+sVEuo8JRdeE+PKhXzkggFoyxstb
/9vzdkn+kHucR4XuubRNlalDvms5K3oZtM29ASdJladVa5OSTMkP7meoLCzSL8iB
roy5U4ufGIChnW18AwIDAQAB

MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMCN7zkRjs/3lyyz
fUNb60EwybLwzBlRxadwNUfWxIXLY8oXjnhHSfDwpwF4IDL6xUS6jwlF14T48qFf
OSCAWjLGy1v/2/N2Sf6Qe5xHhe65tE2VqUO+azkrehm0zb0BJ0mVp1Vrk5JMyQ/u
Z6gsLNIvyIGujLlTi58YgKGdbXwDAgMBAAECgYAph7Nb9Kx/sF/7tS7EM3QXGGW4
YXUz1M4zoeDsAKdcUBTSxqfky0NoYw8yIu2W8T1Q6IfnMRgdxu/V3Ere9q/9OZYb
VFyIHpd7HHtMHVwH79H7BtAETODLXCz6UBTEozyO8ZrIY3A3hroKItcKSDoi0SdY
EPdK+e35Mu2qY0116QJBAO9Xv5H5JB2l+KYzM843eS0iUFMmqw/VhAlF5iMDSZuS
UnUkVE0QPLNr/HyenBhKsBSzHvYuy4I4pFDmG36/yUcCQQDN9JTeUnAZD1rNbKx8
tW7w9iDQyjlBswZqqQJOaook6/xbr4De5V7ITBca50EVfNZS5iE+OCZ7sialgL8B
3dVlAkEAjstPZAu8XGP1IVNTCSlXhnH+cl2TmXLNv6qQTzta4xI9V95A3Wlejb1T
ehY3Etccjnz/b+kjSaH5hrqClPBfaQJALQ+9XqNE2YbNhDKpzqNXwaroZSZJvsEv
vzh5Q7T1wrxLO7g7hwlCYqqbR4yfZdcpgXvOfDGG4fuJjx6LLBpgLQJBAM/0r0CF
HoN8oNM/zcNIUJVthbNWVuzMybcijpdZaYgJa3+FU9RSkwT/TenMSYQnoq/lDVfX
T1bQ+lIjq2RDRE4=
 */
 
class RSAUtils {
	
	//密钥不要有空格和缩进
    const LICAI_RSA_KEY = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/2ww6Jw7bGH7AQ7lGUBYfiaRQ
J00Auwj5Cql5EtxHX9WAUaAHwMluOW9Nr1Ypz3ZHdEJXXlwrAu5WL7hS9GKIR+Zx
/PHQ6O9/v4o2V8KZMJVZYXjvcC0SdgbtiH/lNS0f5T7jAyySvf8kJ3LhdQmiBGCq
C6yfJc0TISRIYIeOCwIDAQAB
-----END PUBLIC KEY-----';

    const DECODE_RSA_KEN = '-----BEGIN RSA PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL/bDDonDtsYfsBD
uUZQFh+JpFAnTQC7CPkKqXkS3Edf1YBRoAfAyW45b02vVinPdkd0QldeXCsC7lYv
uFL0YohH5nH88dDo73+/ijZXwpkwlVlheO9wLRJ2Bu2If+U1LR/lPuMDLJK9/yQn
cuF1CaIEYKoLrJ8lzRMhJEhgh44LAgMBAAECgYATtqBFAWpnXNb5TnwlG2mKiAwY
KFGjN5SuckgDpsp3kwNPEhQNd+O6rbAgHVoPJcATi4CdlZaG3OA8ft7Dt1TAWjvv
tn3x6y6RbwaNrw5yTCiMECfkMLJQ/xi1EwRsWdZvHCVngNZUHdTePG2nuaFx2h60
R4uko5mjufr3Aw0j0QJBAPheKYwUq5j6nycGObyIw9KwivCbFQDoIBmW4TPh4kSp
Z1XQTXHvrpubGBg1c0pLxOTxaBXt0Kh8EE+vMFjC+9UCQQDFwFIUpmMVZLJ1sYDD
0nRTrGHXIakkvRbNgjadZibkjDNUfNDJggtI5tHYgEG3IOCPj45c2QfYskgZDacL
yrJfAkEArpXiNqnBBcQGY/QoWbL5k/ytbfxVg1GoXtSEcWfzGbjK/rNx/QkygAdB
pKLN7Afe2+Al/mQxLH4pKRpIrdxCEQJAB+x23YD1Q2wvgmvEXxRVuOyVVwtwPZqe
CUoIajInqMy9WctOimR9k0Q8cFJjT7UvilEUQUApAlPSc76KTPyoPQJBAI6kTSPp
v5FAaPSNIdU7nI/80UtfDfcH8KlEzQ+gCvk7QwYB/kvioGr3d+ZJRRU4mg5xuXEn
xN1h5lwkzTtb3WY=
-----END RSA PRIVATE KEY-----';


    /**
     * RSA加密
     * @param str
     * @return str
     */
    public function Encode_RSA($str){
        if(!$str){
            return false;
        }
        $encrypted = "";
        $public_key = self::LICAI_RSA_KEY;

        $pu_key = openssl_pkey_get_public($public_key);         //这个函数可用来判断公钥是否是可用的
        if($pu_key){
            openssl_public_encrypt($str,$encrypted,$pu_key);    //公钥加密
            $encrypted = base64_encode($encrypted);	//加密后的内容通常含有特殊字符，需要编码转换下，在网络间通过url传输时要注意base64编码是否是url安全的
        }

        return $encrypted;

    }

    /**
     * RSA解密
     * @param str
     * @return str
     */
    public function deRsa($encrypted){
        $decrypted = '';
        $private_key = self::DECODE_RSA_KEN;

        $pi_key = openssl_pkey_get_private($private_key);	//此函数用来判断私钥是否可用，可用返回资源id
		//openssl_private_encrypt($data,$encrypted,$pi_key);//私钥加密
        openssl_private_decrypt(base64_decode($encrypted),$decrypted,$pi_key);//私钥解密
        return $decrypted;
    }

}

$rsa = new RSAUtils();
$name1 = $rsa->Encode_RSA('110108199002213312');
//$name1 = 'Qk38xXdV9dJqJmsK/c7Ec05czzMYbKve9duVurL74K1XSFU6yVLrVi3tUSrq2KwcOYqKlYKzA+KJKdoxj6N66SxALCKz5qcsnpvXRm1bT/funYDz2OhaFTtzDfXxbaf3aq9O39ZqbIfoJZXzvjwObJbJrLrD4PETf5hHX69VEIo=';
$certno1 = $rsa->deRsa($name1);
echo '加密：'.$name1.'<br/>';
echo '解密：'.$certno1.'<br/>';

