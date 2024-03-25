<?php
// +----------------------------------------------------------------------
// | 文件: api.php
// +----------------------------------------------------------------------
// | 功能: 区块链api接口
// +----------------------------------------------------------------------
// | 时间: 2024-03-25 18:20
// +----------------------------------------------------------------------
// | 作者: webytes<webytes@qq.com>
// +----------------------------------------------------------------------

namespace app\controller;

use Error;
use Exception;
use think\response\Json;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39Mnemonic;
use BitWasp\Bitcoin\Address\PayToPubKeyHashAddress;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory;
use Web3p\EthereumUtil\Util;

class Api
{
    public function index()
    {
        return $this->createMnemonicWord();
    }

    // BTC库(需要运行在64位的php7.0+上, 使用bitwasp库需要安装PHP的gmp扩展) https://github.com/Bit-Wasp/bitcoin-php - composer require bitwasp/bitcoin(要在 php.ini 里面开启 gmp - extension=gmp)
    // ETH库 https://github.com/web3p/ethereum-tx - composer require web3p/ethereum-tx
    // 生成助记词 https://blog.csdn.net/C_jian/article/details/106208207
    // 助记词转换工具 https://bip39.best/ https://iancoleman.io/bip39/
    function createMnemonicWord(){
        // Bip39
        //$math = Bitcoin::getMath();
        //$network = Bitcoin::getNetwork();
        $random = new Random();
        // 生成随机数(initial entropy)
        $entropy = $random->bytes(Bip39Mnemonic::MIN_ENTROPY_BYTE_LEN);
        $bip39 = MnemonicFactory::bip39();
        // 通过随机数生成助记词
        $mnemonic = $bip39->entropyToMnemonic($entropy);
        // 输出助记词
        echo $mnemonic;
    }


    // 助记词转私钥转BTC地址 44'/0'/0'/0/0 最后一个数字代表第几个地址
    function mneToPriBTC($mne)
    {
        $seedGenerator = new Bip39SeedGenerator();
        $seed = $seedGenerator->getSeed($mne);
        
        $hdFactory = new HierarchicalKeyFactory();
        $master = $hdFactory->fromEntropy($seed);
        $hardened = $master->derivePath("44'/0'/0'/0/0"); // 44含义 https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        $prikey = $hardened->getPrivateKey()->toWif(); // 私钥
        $address = new PayToPubKeyHashAddress($hardened->getPublicKey()->getPubKeyHash());
        return ['prikey' => $prikey,'address' => $address->getAddress()];
    }

    // 助记词转私钥转ETH地址 44'/60'/0'/0/0 
    // Polygon (MATIC) https://etherscan.io/token/0x7D1AfA7B718fb893dB30A3aBc0Cfc608AaCfeBB0 Polygon 2.0 (POL) https://etherscan.io/token/0x455e53CBB86018Ac2B8092FdCd39d8444aFFC3F6
    function mneToPriETH($mne)
    {
        $seedGenerator = new Bip39SeedGenerator();
        $seed = $seedGenerator->getSeed($mne,'','0x');
        
        $hdFactory = new HierarchicalKeyFactory();
        $master = $hdFactory->fromEntropy($seed);
        $hardened = $master->derivePath("44'/60'/0'/0/0");
        $prikey  =  $hardened->getPrivateKey()->getHex(); // 私钥
        //私钥转地址
        $util = new Util();
        $address =  $util->publicKeyToAddress($util->privateKeyToPublicKey($prikey));
        return ['prikey'=>$prikey,'address'=>$address];
    }

    /**
     * http://127.0.0.1:8000/api/getkey?keywords=inject gadget hobby velvet sight knock exist slam gadget member spoil stadium
     * 区块链 助记词 转换成 btc 私钥 和 eth 私钥 ，并查询 对应余额 的 demo(主币 或者 代币)
     * @return Json
     */
    public function getKey($keywords)
    {
        try {
            $param = trim($keywords);
            //判断
            if(!$param)
            {
                $res = [
                    "code" => 201,
                    "errorMsg" => 'keywords不能为空'
                    ];
                return json($res);
            }
            //判断是否是助记词
            $strData = explode(" ",$param);
            if(count($strData) == 12)  //助记词导入
            {
                $btcData  = $this->mneToPriBTC($param);
                $etcData  = $this->mneToPriETH($param);
                $res = [
                    "code" => 200,
                    "btcData" => $btcData,
                    "etcData" => $etcData
                    ];
                return json($res);
            } else {
                $res = [
                    "code" => 202,
                    "errorMsg" => 'keywords 必须是12个助记词'
                ];
                return json($res);
            }
        } catch (Error $e) {
            $res = [
                "code" => -1,
                "errorMsg" => ("转换私钥异常" . $e->getMessage())
            ];
            return json($res);
        }
    }
}