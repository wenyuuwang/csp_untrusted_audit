package request;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignatureUser {
	
	String file;
	static String sk;
	//String pk;
	
	public SignatureUser(String str){
		file = str;
		sk = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100c21f755986740d4f81b674b0a0df999eb28ee32f5fafda853cf5dc540a2d1d9ec33e2aad5ed55c0f60fe751f86b7a359efb98dd6a9b35e0b68b6674a95ec954a709ebd1b1456e95ca67129316f249495de21c0ab9db07ba77654b87d3c2674134df106548753440bbf2062025a588bb6316f227b4b4e6831c624ab26394b29fb02030100010281805ba22deacca50b83745f8445bc2ad081311871f572ddb7f11d0d91abba0201f1678878eccdcf395da913748625399a4a61f6dd156f95d3d6dedefb7321c243d5c47fdf71bd3bdc20b0eefd7082819f426388e4b55df0971177e447a467f05cb79d900d5fd22e066044ee41bc0246f4f20b1657a8d9a64cb5766c9aa2067e4c41024100f345a864838ba5c7cb167420afb58caaf129ed1c305a1fc0a0030bc5aca6978827d8cb230f9631fbc3048213e7fc254959a6bde2412f40f88219ef1efc706895024100cc4781450edc6619d02b4126ba1eb6daaee90fc064e167ffdeadd4a173eb9937958395d2deb300dd3f50b6de31b95a5e47432c66518f4fc61db1c057baa2544f024041c995a750f7a3e66ae27097224d4b7432f1aea08fe6df6d5d1855c7a85008ec963207853cc2d6538a429ed6b946b3e2a92ef16ccd49f51cff39fa337bfafe1d024053edb4f0d89038eab61a6f6427e7e29caa6c5aea63083120712ede438f4ae6e26d6d68ab00906ef477c503bcfa94fac9ed616de683efeb88ac3e9195f9ba24050241008b014e154f824222226994c63492484678b5852b6dd3b59b3f3b1a389462057fda3d17f8c4cd3f57995df57538b298b0c0387bb34f1fc69e882d93ec9efbbb26";
		//pk = "30819f300d06092a864886f70d010101050003818d0030818902818100c21f755986740d4f81b674b0a0df999eb28ee32f5fafda853cf5dc540a2d1d9ec33e2aad5ed55c0f60fe751f86b7a359efb98dd6a9b35e0b68b6674a95ec954a709ebd1b1456e95ca67129316f249495de21c0ab9db07ba77654b87d3c2674134df106548753440bbf2062025a588bb6316f227b4b4e6831c624ab26394b29fb0203010001";
	}
	
	/**
	 * To sign with user's private key
	 * @param file
	 */
	public static void signFile(String file){
		//temp
		String location = "";
		try {
			BufferedReader read_file = new BufferedReader(new FileReader(location+file));
			StringBuilder content = new StringBuilder();
			String str = null;
			while((str = read_file.readLine()) != null)
				content.append(str+"\n");
			//这是GenerateKeyPair输出的私钥编码
			String prikeyvalue = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100c21f755986740d4f81b674b0a0df999eb28ee32f5fafda853cf5dc540a2d1d9ec33e2aad5ed55c0f60fe751f86b7a359efb98dd6a9b35e0b68b6674a95ec954a709ebd1b1456e95ca67129316f249495de21c0ab9db07ba77654b87d3c2674134df106548753440bbf2062025a588bb6316f227b4b4e6831c624ab26394b29fb02030100010281805ba22deacca50b83745f8445bc2ad081311871f572ddb7f11d0d91abba0201f1678878eccdcf395da913748625399a4a61f6dd156f95d3d6dedefb7321c243d5c47fdf71bd3bdc20b0eefd7082819f426388e4b55df0971177e447a467f05cb79d900d5fd22e066044ee41bc0246f4f20b1657a8d9a64cb5766c9aa2067e4c41024100f345a864838ba5c7cb167420afb58caaf129ed1c305a1fc0a0030bc5aca6978827d8cb230f9631fbc3048213e7fc254959a6bde2412f40f88219ef1efc706895024100cc4781450edc6619d02b4126ba1eb6daaee90fc064e167ffdeadd4a173eb9937958395d2deb300dd3f50b6de31b95a5e47432c66518f4fc61db1c057baa2544f024041c995a750f7a3e66ae27097224d4b7432f1aea08fe6df6d5d1855c7a85008ec963207853cc2d6538a429ed6b946b3e2a92ef16ccd49f51cff39fa337bfafe1d024053edb4f0d89038eab61a6f6427e7e29caa6c5aea63083120712ede438f4ae6e26d6d68ab00906ef477c503bcfa94fac9ed616de683efeb88ac3e9195f9ba24050241008b014e154f824222226994c63492484678b5852b6dd3b59b3f3b1a389462057fda3d17f8c4cd3f57995df57538b298b0c0387bb34f1fc69e882d93ec9efbbb26";	
			PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(hexStrToBytes(prikeyvalue)); 
			//PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(keys.getPrivate().getEncoded()); 
			KeyFactory keyf=KeyFactory.getInstance("RSA");
			PrivateKey myprikey=keyf.generatePrivate(priPKCS8);
			// 用私钥对信息生成数字签名
			Signature signet = Signature.getInstance("MD5withRSA");
			signet.initSign(myprikey);
			signet.update(content.toString().getBytes("ISO-8859-1"));
			byte[] signed = signet.sign(); // 对信息的数字签名
			BufferedWriter sign_file = new BufferedWriter(new FileWriter(location+file, true));
			sign_file.write("signature#");
			sign_file.write(bytesToHexStr(signed)+"\n");
			sign_file.close();
		} catch (java.lang.Exception e) {
				e.printStackTrace();
				System.out.println("签名并生成文件失败");
		}
	}

	/**
	 * To check if signature for data block is from owner.
	 * @param padding
	 * @param withPadding
	 * @return
	 */
	public boolean verifySig(String padding, boolean withPadding){
		boolean correctSig = false;
		try {
			//这是GenerateKeyPair输出的公钥编码
			String pubkeyvalue = "30819f300d06092a864886f70d010101050003818d0030818902818100acd21e764d563d091eb652b12bb2f2a886ec03678d578002d0f550d74fef90363ebdd2aacc87b931e37b5641"
					+ "12c8279f40cfb3bc1c9aff0841629188fab0d69e5d011063335c90a1488c6fb4f20d88fdb261738b1f5b797dcee91373b57e9ef6f465b45f93181ac79fa9279bc8f9e9fbc5559f790db1153f9624301180cfe25b0203010001";
			//content
			BufferedReader read_file = new BufferedReader(new FileReader(file));
			StringBuffer content = new StringBuffer();
			StringBuffer sig = new StringBuffer();
			String str = null;
			while((str = read_file.readLine()) != null){
				content.append(str+"\n");
			}
			if(withPadding){
				content.append(padding+"\n");
				System.out.println("padding: "+ padding);
			}
			read_file.close();
			
			//read signature
			BufferedReader read_sig = new BufferedReader(new FileReader(file+".sig"));
			while((str = read_sig.readLine()) != null){
				System.out.println("sig:"+str);
				sig.append(str+"\n");
			}
			read_sig.close();
			byte[] signed = hexStrToBytes(sig.toString());			
			
			//verify
			X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(hexStrToBytes(pubkeyvalue));
			//X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);			
			Signature signetcheck=Signature.getInstance("MD5withRSA");
			signetcheck.initVerify(pubKey);
			signetcheck.update(content.toString().getBytes());
			if (signetcheck.verify(signed)) {
				System.out.println("签名正常");
				correctSig = true;
			}
			else {
				System.out.println("非签名正常");
				correctSig = false;
			}
		} catch (java.lang.Exception e) {
			e.printStackTrace();
		}
		return correctSig;
		
	}
	
	/**
	 * To check if file is signed by owner.
	 * @param file: The file to be checked
	 * @return
	 */
	public static boolean verifyInnerSig(String file){
		boolean correctSig = false;
		String location = "";
				
		try {
			//这是GenerateKeyPair输出的公钥编码
			String pubkeyvalue = "30819f300d06092a864886f70d010101050003818d0030818902818100acd21e764d563d091eb652b12bb2f2a886ec03678d578002d0f550d74fef90363ebdd2aacc87b931e37b5641"
					+ "12c8279f40cfb3bc1c9aff0841629188fab0d69e5d011063335c90a1488c6fb4f20d88fdb261738b1f5b797dcee91373b57e9ef6f465b45f93181ac79fa9279bc8f9e9fbc5559f790db1153f9624301180cfe25b0203010001";
			//content
			BufferedReader read_file = new BufferedReader(new FileReader(location+file));
			StringBuffer content = new StringBuffer();
			StringBuffer sig = new StringBuffer();
			String str = null;
			String[] array;
			while((str = read_file.readLine()) != null){
				//System.out.println(str);
				array = str.split("#");
				if(!array[0].equals("signature"))
					content.append(str+"\n");
				else{
					sig.append(array[1]+"\n");
					break;
				}
			}
			
			//read more signature (in case the signature occupies more than one line)
			while((str = read_file.readLine()) != null){
				sig.append(str+"\n");
				System.out.println("more sig ... ");
			}
			read_file.close();
			byte[] signed = hexStrToBytes(sig.toString());			
			

	
			//verify
			X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(hexStrToBytes(pubkeyvalue));
			//X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(keys.getPublic().getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyFactory.generatePublic(bobPubKeySpec);			
			Signature signetcheck=Signature.getInstance("MD5withRSA");
			signetcheck.initVerify(pubKey);
			signetcheck.update(content.toString().getBytes());
			if (signetcheck.verify(signed)) {
				System.out.println("签名正常");
				correctSig = true;
			}
			else {
				System.out.println("非签名正常");
				correctSig = false;
			}
		} catch (java.lang.Exception e) {
			e.printStackTrace();
		}
		return correctSig;
	}
	
	public static final byte[] hexStrToBytes(String s) {
		byte[] bytes;	
		bytes = new byte[s.length() / 2];	
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}
	
	public static final String bytesToHexStr(byte[] bcd) {
		
		final char[] bcdLookup = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };		
		StringBuffer s = new StringBuffer(bcd.length * 2);
	
		for (int i = 0; i < bcd.length; i++) {
			s.append(bcdLookup[(bcd[i] >>> 4) & 0x0f]);
			s.append(bcdLookup[bcd[i] & 0x0f]);
		}	
		return s.toString();
	}
}
