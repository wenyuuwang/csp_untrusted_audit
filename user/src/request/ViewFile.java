package request;

import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.swing.*;


public class ViewFile {
	
	/**
	 * To decrypt file (for multiple times if readLoop is larger than 1)
	 * Data blocks and corresponding .sig files should be located under the directory "/blocks"
	 * @param urlFile
	 * @param readLoop: repeat the operation.
	 */
	public static void decrypt_and_view(String urlFile, int readLoop){
		
		//create frame
		JFrame view_frame = new JFrame();;
		JTextArea view_words = new JTextArea(20, 30);		
		//add component
		view_frame.add(new JLabel("Sharing file:"), BorderLayout.NORTH);	
		JScrollPane jsp = new JScrollPane(view_words);
		view_words.setLineWrap(true);
		view_words.setWrapStyleWord(true);
		view_frame.add(jsp, BorderLayout.CENTER);
		
		
		BufferedReader read_blockID, readEncrypt;
		StringBuffer content = new StringBuffer();
		StringBuffer content_en = new StringBuffer();
		String str, str_de;
		String[] array_content;
		try{
			do{
				read_blockID = new BufferedReader(new FileReader(urlFile));
				SignatureUser checkSig;
				while((str = read_blockID.readLine()) != null){
					array_content = str.split("#");			
					if(!array_content[0].equals("file")){
						//if signature is correct, decrypt file
						checkSig = new SignatureUser("blocks/"+array_content[0]);
						System.out.println("check sig: "+array_content[0]);
						if(checkSig.verifySig("blockHash#"+array_content[2],true)){ //[2] is hash of block
							readEncrypt = new BufferedReader(new FileReader("blocks/"+array_content[0]));
							System.out.println("decrypt: "+array_content[0]);
							while((str=readEncrypt.readLine()) != null){
								content_en.append(str);
								str_de = AES128.decrypt(str, "file_key") + "\n";
								content.append(str_de);
								str = null; str_de = null;
							}
							readEncrypt.close();
						}else{							
							JOptionPane.showMessageDialog(null, "signature error ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
							System.exit(0);
						}
					}
					
				}
				read_blockID.close();
				readLoop --;
			}while(readLoop > 0);
			
			view_words.setText(content.toString());
			
			//set frame
			view_frame.setResizable(false);
			view_frame.setVisible(true);		
			int w = (Toolkit.getDefaultToolkit().getScreenSize().width - 300) / 2;
			int h = (Toolkit.getDefaultToolkit().getScreenSize().height - 200) / 2;
			view_frame.setLocation(w, h);
			view_frame.setSize(400, 500);
			view_frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
			
		}catch (IOException e) {
			e.printStackTrace();
			JOptionPane.showMessageDialog(null, "fail to decrypt ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
		}
		
	}

}
