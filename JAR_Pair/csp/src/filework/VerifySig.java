package filework;

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

public class VerifySig {
	
	String file;
	
	public VerifySig(String str){
		file = str;
	}
	
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
			String[] array;
			while((str = read_file.readLine()) != null){
				content.append(str+"\n");
			}
			if(withPadding){
				content.append(padding+"\n");
				//System.out.println(padding);
			}
			read_file.close();
			
			//read signature
			BufferedReader read_sig = new BufferedReader(new FileReader(file+".sig"));
			while((str = read_sig.readLine()) != null){
				//System.out.println(str);
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
	
	public static boolean verifyInnerSig(String file){
		boolean correctSig = false;

		boolean isJar = true;
		String location;
		if(!isJar)
			location = "";
		else
			location = "blocks_pre/";
		
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
			
			//read signature
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
	/**
	 * copied from owner_project. modified.To sign permission
	 */
	 public static void sign_file(String file){
			//temp
			//String location = "file/";
			//String[] array_filename = file.split("\\.");
			try {
				BufferedReader read_file = new BufferedReader(new FileReader(file));
				StringBuilder content = new StringBuilder();
				String str = null;
				while((str = read_file.readLine()) != null)
					content.append(str+"\n");
				//这是GenerateKeyPair输出的私钥编码
				String prikeyvalue = "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100acd21e764d563d091eb652b12bb2f2a886ec03678d578002d0f550d74fef90363ebdd2aacc87b931e37b564112c8279f40cfb3bc1c9aff0841629188fab0d69e5d011063335c90a1488c6fb4f20d88fdb261738b1f5b797dcee91373b57e9ef6f465b45f93181ac79fa9279bc8f9e9fbc5559f790db1153f9624301180cfe25b0203010001028180663c7f4cd8ff756819c51e323579cd57a949a1d1f6a996cf13b2ac3a53cd92f0a43943914b21d78b0dd9fef2cc1ba064f3c06bc192e29690d9a"
						+ "d680f32cebe8743fc44b0166832b9880090a4f5ce26a483d268af6add29d7127a5b13d7c294294cb0951a72d37ad362e6b7d15402ce4fcd3ee320bc4cefe66699e2af602d0821024100d2a5f0b394f7c8bf8143a6242d66a1aa4c92208a52ab303771f98fae6079c581bb2575cad1c83ebd8799700ea40e5da9ff55bcbe9d3eb2be281624f2cbecb583024100d207497e7f80b445cf4cbeb334e8da135f1bb7d52ece56b0d0b0d41001ca9910da0c8ea48cd17763deeaffd3f4d5fafee1ba5043161e8d1ce01d2b4b7b956049024100b2b992a97bca64ac7f8b9b4a74aef099e28fd546277011dfe9373a3e54a2dcfdfe808119cdb65ded4740db7fc09863c619db6fe236de7c9fb4b95d2e17f1c5eb024100aa288d3a974246cb682fdd3083654388fe3d0eab00c8db2355706ddeaa14e1fded2acf4631706331dea0b5b39b60e1812e902c06ae1d0266aa8bf74fa84855410240599c460c76efc42da922800e6edd6816d57804b8524f92159d19ba85b6a5d8acfb6fe0b4feaccdb4c2da9aed960d341041b00a7763767f89f46b9d15fcba96c1";
				PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(hexStrToBytes(prikeyvalue)); 
				//PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(keys.getPrivate().getEncoded()); 
				KeyFactory keyf=KeyFactory.getInstance("RSA");
				PrivateKey myprikey=keyf.generatePrivate(priPKCS8);
				// 用私钥对信息生成数字签名
				Signature signet = Signature.getInstance("MD5withRSA");
				signet.initSign(myprikey);
				signet.update(content.toString().getBytes("ISO-8859-1"));
				byte[] signed = signet.sign(); // 对信息的数字签名
				BufferedWriter sign_file = new BufferedWriter(new FileWriter(file, true));
				sign_file.write("signature#");
				sign_file.write(bytesToHexStr(signed)+"\n");
				sign_file.close();
			} catch (java.lang.Exception e) {
					e.printStackTrace();
					System.out.println("签名并生成文件失败");
			}
		}
	 
	 /**
	  * return content's singature
	  * @param file
	  */
	 public static String sign_file_return (String content){
			try {
				//这是GenerateKeyPair输出的私钥编码
				String prikeyvalue = "30820277020100300d06092a864886f70d0101010500048202613082025d02010002818100acd21e764d563d091eb652b12bb2f2a886ec03678d578002d0f550d74fef90363ebdd2aacc87b931e37b564112c8279f40cfb3bc1c9aff0841629188fab0d69e5d011063335c90a1488c6fb4f20d88fdb261738b1f5b797dcee91373b57e9ef6f465b45f93181ac79fa9279bc8f9e9fbc5559f790db1153f9624301180cfe25b0203010001028180663c7f4cd8ff756819c51e323579cd57a949a1d1f6a996cf13b2ac3a53cd92f0a43943914b21d78b0dd9fef2cc1ba064f3c06bc192e29690d9a"
						+ "d680f32cebe8743fc44b0166832b9880090a4f5ce26a483d268af6add29d7127a5b13d7c294294cb0951a72d37ad362e6b7d15402ce4fcd3ee320bc4cefe66699e2af602d0821024100d2a5f0b394f7c8bf8143a6242d66a1aa4c92208a52ab303771f98fae6079c581bb2575cad1c83ebd8799700ea40e5da9ff55bcbe9d3eb2be281624f2cbecb583024100d207497e7f80b445cf4cbeb334e8da135f1bb7d52ece56b0d0b0d41001ca9910da0c8ea48cd17763deeaffd3f4d5fafee1ba5043161e8d1ce01d2b4b7b956049024100b2b992a97bca64ac7f8b9b4a74aef099e28fd546277011dfe9373a3e54a2dcfdfe808119cdb65ded4740db7fc09863c619db6fe236de7c9fb4b95d2e17f1c5eb024100aa288d3a974246cb682fdd3083654388fe3d0eab00c8db2355706ddeaa14e1fded2acf4631706331dea0b5b39b60e1812e902c06ae1d0266aa8bf74fa84855410240599c460c76efc42da922800e6edd6816d57804b8524f92159d19ba85b6a5d8acfb6fe0b4feaccdb4c2da9aed960d341041b00a7763767f89f46b9d15fcba96c1";
				PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(hexStrToBytes(prikeyvalue)); 
				//PKCS8EncodedKeySpec priPKCS8=new PKCS8EncodedKeySpec(keys.getPrivate().getEncoded()); 
				KeyFactory keyf=KeyFactory.getInstance("RSA");
				PrivateKey myprikey=keyf.generatePrivate(priPKCS8);
				// 用私钥对信息生成数字签名
				Signature signet = Signature.getInstance("MD5withRSA");
				signet.initSign(myprikey);
				signet.update(content.toString().getBytes("ISO-8859-1"));
				byte[] signed = signet.sign(); // 对信息的数字签名
				return bytesToHexStr(signed);
				/*BufferedWriter sign_file = new BufferedWriter(new FileWriter(file, true));
				sign_file.write("signature#");
				sign_file.write(bytesToHexStr(signed)+"\n");
				sign_file.close();*/
			} catch (java.lang.Exception e) {
					e.printStackTrace();
					System.out.println("签名并生成文件失败");
			}
			return "out of expection";
			
		}
}
