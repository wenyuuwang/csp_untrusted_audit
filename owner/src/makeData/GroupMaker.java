package makeData;

import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
/**
 * For group dynamics. ACL stands for "access list".
 * @author wendywang
 *
 */
public class GroupMaker {
	
	public static void EncryptACL(String filename){
		String location = "file/";
		String[] array_filename = filename.split("\\.");
		try {
			BufferedReader read_list = new BufferedReader(new FileReader(location+filename));
			BufferedWriter write_en_list = new BufferedWriter(new FileWriter(location+array_filename[0]+"_en.txt", false));
			String str_user;
			String [] array_user;
			while((str_user = read_list.readLine()) != null){
				//write_en_list.write(Encrypt.encrypt(str_user, "userlist_key")+"\n");	//encrypt all
				array_user = str_user.split("#");
				if(array_user[0].equals("add") || array_user[0].equals("revoke")){
					write_en_list.write(array_user[0]+"#"+Encrypt.encrypt(array_user[1], "userlist_key")+"\n");
				}else if(array_user[0].equals("sharingGroup")){
					write_en_list.write(str_user+"\n");
				}else{
					write_en_list.write(Encrypt.encrypt(str_user, "userlist_key")+"\n");
				}
			}
			read_list.close();
			write_en_list.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	
	
	
	/* public static boolean verifySig(String file){
		boolean correctSig = false;
		//temp
		String location = "/Users/wendywang/Desktop/";
		
		try {
			//这是GenerateKeyPair输出的公钥编码
			String pubkeyvalue = "30819f300d06092a864886f70d010101050003818d0030818902818100acd21e764d563d091eb652b12bb2f2a886ec03678d578002d0f550d74fef90363ebdd2aacc87b931e37b5641"
					+ "12c8279f40cfb3bc1c9aff0841629188fab0d69e5d011063335c90a1488c6fb4f20d88fdb261738b1f5b797dcee91373b57e9ef6f465b45f93181ac79fa9279bc8f9e9fbc5559f790db1153f9624301180cfe25b0203010001";
			//content
			BufferedReader read_file = new BufferedReader(new FileReader(location+file));
			StringBuffer content = new StringBuffer();
			String str = null;
			while((str = read_file.readLine()) != null){
				content.append(str);
			}
			read_file.close();

			//signature
			BufferedReader read_sig = new BufferedReader(new FileReader(location+file+".sig"));
			StringBuffer sig = new StringBuffer();
			while((str = read_sig.readLine()) != null)
				sig.append(str);
			byte[] signed = hexStrToBytes(sig.toString());
			read_sig.close();
			
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
	}*/
}
