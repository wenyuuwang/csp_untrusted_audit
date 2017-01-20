package access;

import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.io.*;

import javax.swing.*;

import filework.AES128;
import filework.VerifySig;

public class AccessFile {

	public AccessFile(){
	}
	
	/**
	 * no calling of this method at CSP
	 * now implemented in User JAR.
	 * @param fileID
	 */
	public void decrypt_and_view(String fileID){
		String[] blockid_array = fileID.split("\\.");
		
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
		String str;
		String[] array_content;
		try{			
			//read
			/*if(!isJar)
				readEncrypt = new FileInputStream(new File(file_en));	//run in eclipse
			else 
				//readEncrypt = this.getClass().getResourceAsStream(file_en);//for jar; file is in jar
				readEncrypt = new FileInputStream(new File(file_en));*/
			
			InputStream strm = this.getClass().getResourceAsStream("/"+ blockid_array[0]+"/blockID.txt");	
			read_blockID = new BufferedReader(new InputStreamReader(strm, "UTF-8"));
			VerifySig checkSig;
			while((str = read_blockID.readLine()) != null){
				array_content = str.split("#");			
				if(!array_content[0].equals("file")){
					//if signature is correct, decrypt file
					checkSig = new VerifySig("blocks/"+array_content[0]);
					System.out.println("check sig: "+array_content[0]);
					if(checkSig.verifySig("blockHash#"+array_content[2],true)){
						readEncrypt = new BufferedReader(new FileReader("blocks/"+array_content[0]));
						System.out.println("decrypt: "+array_content[0]);
						while((str=readEncrypt.readLine()) != null){
							content_en.append(str);
							content.append(AES128.decrypt(str, "file_key") + "\n");
						}
						readEncrypt.close();
					}else{							
						JOptionPane.showMessageDialog(null, "signature error ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
						System.exit(0);
					}
				}
				
			}
			read_blockID.close();
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
	
	/**
	 * To specify url for blocks that user want.
	 * The url file name and directory name for blocks need modifying for an accurate match with user request
	 * @param fileID
	 */
	public void makeURL(String fileID){
		String[] blockid_array = fileID.split("\\.");
		try {
			BufferedWriter w = new BufferedWriter(new FileWriter(blockid_array[0] + "_url.txt"));
			//The implementation of request-permission is later than the time when this Class was composed,
			//thus reader had better get source from "Request" of user, in accordance with block selection at user.
			InputStream strm = this.getClass().getResourceAsStream("/"+ blockid_array[0]+"/blockID.txt");	
			BufferedReader read_blockID = new BufferedReader(new InputStreamReader(strm, "UTF-8"));	
			String str;
			while((str = read_blockID.readLine()) != null){
				w.write(str+"\n");
			}
			read_blockID.close();
			w.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
