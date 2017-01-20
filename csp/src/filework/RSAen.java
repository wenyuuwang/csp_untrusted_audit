package filework;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.io.*;
import java.math.*;

public class RSAen {
	public static String encrypt(String plain) throws Exception {
		String s = plain;

		// 获取公钥及参数e,n
		FileInputStream f = new FileInputStream("pubkey.dat");
		ObjectInputStream b = new ObjectInputStream(f);
		RSAPublicKey pbk = (RSAPublicKey) b.readObject();
		BigInteger e = pbk.getPublicExponent();
		BigInteger n = pbk.getModulus();
		//System.out.println("e= " + e);
		//System.out.println("n= " + n);
		// 获取明文m
		byte ptext[] = s.getBytes("UTF-8");
		BigInteger m = new BigInteger(ptext);
		// 计算密文c
		BigInteger c = m.modPow(e, n);
		//System.out.println("c= " + c);
		// 保存密文
		/*String cs = c.toString();
		BufferedWriter out =
			new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream("encrypt.txt")));
		out.write(cs, 0, cs.length());
		out.close();*/
		
		//System.out.println("plain:"+ s.length());
		//System.out.println("en:"+c.toString().length());
		
		//decrypt(c.toString());
		return c.toString();
	}
	
	public static void decrypt(String en) throws Exception {
		// 读取密文
		String ctext = en;
		BigInteger c = new BigInteger(ctext);
		// 读取私钥
		FileInputStream f = new FileInputStream("privatekey.dat");
		ObjectInputStream b = new ObjectInputStream(f);
		RSAPrivateKey prk = (RSAPrivateKey) b.readObject();
		BigInteger d = prk.getPrivateExponent();
		// 获取私钥参数及解密
		BigInteger n = prk.getModulus();
		//System.out.println("d= " + d);
		//System.out.println("n= " + n);
		BigInteger m = c.modPow(d, n);
		// 显示解密结果
		//System.out.println("m= " + m);
		byte[] mt = m.toByteArray();
		System.out.println("PlainText is ");
		for (int i = 0; i < mt.length; i++) {
			System.out.print((char) mt[i]);
		}
	}
}
