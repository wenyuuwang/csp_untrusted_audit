package request;

import java.security.SecureRandom;  
import java.util.Scanner;  
import javax.crypto.Cipher;  
import javax.crypto.KeyGenerator;  
import javax.crypto.SecretKey;  
import javax.crypto.spec.SecretKeySpec;  
/** 
 *  
 * @author xiangxg 
 * aes 128加密器 
 * 
 */  
  
public class AES128 {  
  
    /** 
     * 解密 
     *  
     * @param content 
     *            待解密内容 
     * @return 
     */  
    public static String decrypt(String content, String key) {  
          
        try {  
            byte[] decryptFrom = parseHexStr2Byte(content);  
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器  
            cipher.init(Cipher.DECRYPT_MODE, genKey(key));// 初始化  
            byte[] result = cipher.doFinal(decryptFrom);  
            return new String(result); // 加密  
        } catch (Exception e) {  
            e.printStackTrace();  
        }   
        return null;  
    } 
    
    public static String encrypt(String content, String strkey) {  
        
	    try {  
	        Cipher cipher = Cipher.getInstance("AES");// 创建密码器  
	        byte[] byteContent = content.getBytes("utf-8");  
	        cipher.init(Cipher.ENCRYPT_MODE, genKey(strkey));// 初始化  
	        byte[] result = cipher.doFinal(byteContent);  
	        return parseByte2HexStr(result); // 加密  
	    } catch (Exception e) {  
	        e.printStackTrace();  
	    }   
	    return null;  
		  
	}  
      
    /** 
     * 根据密钥获得 SecretKeySpec 
     * @return 
     */  
    private  static SecretKeySpec genKey(String strKey){  


    	//String strKey = "veir_12345";// 加密解密密钥
        byte[] enCodeFormat = {0}; ;  
        try {  
            KeyGenerator kgen = KeyGenerator.getInstance("AES");  
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG"  );     
            secureRandom.setSeed(strKey.getBytes());     
            kgen.init(128, secureRandom);  
            SecretKey secretKey = kgen.generateKey();  
            enCodeFormat = secretKey.getEncoded();  
              
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
          
        return new SecretKeySpec(enCodeFormat, "AES");  
    }  
  
      
  
    /** 
     * 将二进制转换成16进制 
     *  
     * @param buf 
     * @return 
     */  
    private static String parseByte2HexStr(byte buf[]) {  
        StringBuffer sb = new StringBuffer();  
        for (int i = 0; i < buf.length; i++) {  
            String hex = Integer.toHexString(buf[i] & 0xFF);  
            if (hex.length() == 1) {  
                hex = '0' + hex;  
            }  
            sb.append(hex.toUpperCase());  
        }  
        return sb.toString();  
    }  
  
    /** 
     * 将16进制转换为二进制 
     *  
     * @param hexStr 
     * @return 
     */  
    private static byte[] parseHexStr2Byte(String hexStr) {  
        if (hexStr.length() < 1)  
            return null;  
        byte[] result = new byte[hexStr.length() / 2];  
        for (int i = 0; i < hexStr.length() / 2; i++) {  
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);  
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),  
                    16);  
            result[i] = (byte) (high * 16 + low);  
        }  
        return result;  
    }  
      
  
    /*public static void main(String[] args) {  
          
          
        Scanner s = new Scanner(System.in);  
        System.out.println("Please input the encode content (input 'exit' to exit)!");  
        System.out.print("content:");  
          
        while(s.hasNext()){  
             String content = s.next();  
            if(content.equalsIgnoreCase("exit")){  
                System.exit(0);  
            }  
            System.out.println("Generate password success!");  
            System.out.print("password:");  
            String en_word = AES128.encrypt(content); //length = 32
            System.out.println(en_word+"\n"); 
            String de_word = AES128.decrypt(en_word);
            System.out.println(de_word+"\n"); 
           
        }  
          
    } */ 
  
}  
