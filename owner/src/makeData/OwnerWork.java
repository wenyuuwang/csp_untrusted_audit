package makeData;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
/**
 * Owner can 1. encrypt file and sign; 2.encrypt ACL(see GroupMaker) 
 * @author wendywang
 *
 */
public class OwnerWork {
	/**
	 * To check if signature is correct. May not be used in owner.
	 * @param file
	 * @return
	 */
	public static boolean verifySig(String file){
		boolean correctSig = false;

		String location = "file/";
		
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
				//System.out.println("array[0]: "+array[0]);
				if(!array[0].equals("signature"))
					content.append(str+"\n");
				else{
					sig.append(array[1]+"\n");
					break;
				}
			}
			while((str = read_file.readLine()) != null){
				sig.append(str);
				System.out.println("more sig: " + str);
			}				
			//System.out.println(sig.toString());
			byte[] signed = hexStrToBytes(sig.toString());			
			read_file.close();

			//signature
			/*BufferedReader read_sig = new BufferedReader(new FileReader(location+file+".sig"));
			StringBuffer sig = new StringBuffer();
			while((str = read_sig.readLine()) != null)
				sig.append(str);
			byte[] signed = hexStrToBytes(sig.toString());
			read_sig.close();*/
			
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

	public static void main(String[] args) {
		long t1, t2; 
		ArrayList<String> filenames = new ArrayList<String>();
		//decide files to encrypt
		int size = 1;		
		for(int i=1; i<size+1; i++){
			filenames.add("text_"+i+".txt");
		}
		
		//file content
		/*FileMaker ownerFile1 = new FileMaker("text_16m.txt");
		ownerFile1.encryptFile();
		ownerFile1.addHashSig();*/
		
		String[] array_name;
		t1 = System.currentTimeMillis();	
		for(String name : filenames){
			FileMaker ownerFile2 = new FileMaker(name);
			ownerFile2.encryptFile();
			ownerFile2.addHashSig();
			array_name = name.split("\\.");
			System.out.println(array_name[0]);
			System.out.println(OwnerWork.verifySig(array_name[0]+"_encrypt.txt"));
		}		
		t2 = System.currentTimeMillis(); 
		System.out.println("["+size+"]程序运行时间： "+(t2-t1)+"ms"); 		
		
		//access list
		
		//GroupMaker.EncryptACL();
		/*ArrayList<String> filenames = new ArrayList<String>();
		filenames.add("valid_user_add200.txt");
		filenames.add("valid_user_add400.txt");
		filenames.add("valid_user_add600.txt");
		filenames.add("valid_user_add800.txt");
		filenames.add("valid_user_add1000.txt");
		for(String name : filenames){
			String[] array = name.split("\\.");
			t1 = System.currentTimeMillis();
			GroupMaker.EncryptACL(name);
			Encrypt.sign_file(array[0]+"_en.txt");
			t2 = System.currentTimeMillis(); 
			System.out.println("["+name+"]程序运行时间： "+(t2-t1)+"ms"); 			
			//System.out.println(OwnerWork.verifySig(array[0]+"_en.txt"));
		}*/
		

		
	}

}
