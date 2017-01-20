package request;

import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.*;

/**
 * A user can
 * 1. "Request"-make a request to see file, 
 * 2."View"-decrypt file after ensuring signature is correct.
 * @author wendywang
 *
 */

public class Request implements ActionListener {
	JFrame user_frame;
	JButton user_confirm, user_view, user_cancel;
	JTextField hashID_field, idVersion_field, filename_field;
	String hashID, filename, user_ver;
	
	
	public Request(){
		user_frame = new JFrame();
		user_frame.setLayout(new GridLayout(4,1));
		//hashID
		JPanel hashID_panel = new JPanel();
		JLabel hashID_label= new JLabel("HashID:");
		hashID_field = new JTextField("8F3B3B92DE1B289895032313874E5513E280DFEF", 12);
		hashID_panel.add(hashID_label);
		hashID_panel.add(hashID_field);
		user_frame.add(hashID_panel);
		//ID version
		JPanel idVersion_panel = new JPanel();
		JLabel idVersion_label = new JLabel("ID version:");
		idVersion_field = new JTextField(12);
		idVersion_panel.add(idVersion_label);
		idVersion_panel.add(idVersion_field);
		user_frame.add(idVersion_panel);
		//block ID
		JPanel blockID_panel = new JPanel();
		JLabel blockID_label = new JLabel("blockID:");
		filename_field = new JTextField("text.txt", 12);
		blockID_panel.add(blockID_label);
		blockID_panel.add(filename_field);
		user_frame.add(blockID_panel);
		//buttons
		JPanel button_panel1 = new JPanel();		
		user_confirm = new JButton("Requst");
		user_view = new JButton("View");
		user_cancel = new JButton("Cancel");		
		button_panel1.add(user_confirm);
		button_panel1.add(user_view);
		button_panel1.add(user_cancel);	
		user_confirm.addActionListener(this);
		user_view.addActionListener(this);
		user_cancel.addActionListener(this);
		user_frame.add(button_panel1);		
		
		//set frame size
		user_frame.setResizable(false);
		user_frame.setVisible(true);		
		int w = (Toolkit.getDefaultToolkit().getScreenSize().width - 300) / 2;
		int h = (Toolkit.getDefaultToolkit().getScreenSize().height - 200) / 2;
		user_frame.setLocation(w, h);
		user_frame.setSize(300, 200);
		user_frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}


	@Override
	public void actionPerformed(ActionEvent e) {
		JButton clicked = (JButton)e.getSource();
		if(clicked == user_cancel){		
			user_frame.dispose();
			System.exit(0);
		}else if(clicked == user_confirm){
			//long t1, t2; 
			
			//t1 = System.currentTimeMillis();
			hashID = hashID_field.getText();
			filename = filename_field.getText();
			user_ver = idVersion_field.getText();
			user_frame.dispose();
			//Create a "Reqeust" file in format below.
			//the last part(12332112345) in request could be deleted or generated as random number.
			String request = "REQUEST#" + hashID + "#ver" + user_ver + "#" + filename + "#12332112345\n";
			try {
				BufferedWriter write_request = new BufferedWriter(new FileWriter("request.txt"));
				write_request.write(request);
				write_request.close();
				SignatureUser.signFile("request.txt");
			} catch (IOException e1) {
				//t2 = System.currentTimeMillis(); 
				//System.out.println("[程序运行时间]： "+(t2-t1)+"ms");
				e1.printStackTrace();
			}
			//t2 = System.currentTimeMillis(); 
			//System.out.println("[程序运行时间]： "+(t2-t1)+"ms"); 
			Request r1 = new Request();
		}else if(clicked == user_view){
			//decryption procedure:
			//check Permission Sig -> check Permission content -> decrypt blocks according to "url.txt"
			long t1, t2; 		
			t1 = System.currentTimeMillis();
			if(SignatureUser.verifyInnerSig("permission.txt")){
				try {
					BufferedReader readRequest = new BufferedReader(new FileReader("request.txt"));
					BufferedReader readPermission = new BufferedReader(new FileReader("permission.txt"));
					String[] req = readRequest.readLine().split("#", 2);
					String[] per = readPermission.readLine().split("#", 2);
					readRequest.close();
					readPermission.close();
					if(req[0].equals("REQUEST") && per[0].equals("PERMIT") && req[1].equals(per[1])){
						filename = filename_field.getText();
						String[] array_name = filename.split("\\.");
						//modify the second param to set looping time
						//for efficiency evaluation in experiment
						//set it to 1 as default.
						//url contains the block id and block hash
						ViewFile.decrypt_and_view(array_name[0]+"_url.txt", 1);
					}else{
						System.out.println("permission content error");
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				} catch (IOException e1) {
					e1.printStackTrace();
				}				
			}else{
				System.out.println("permission signature error.");
			}
			t2 = System.currentTimeMillis(); 
			System.out.println("[程序运行时间]： "+(t2-t1)+"ms"); 
		}
		
	}
	
	public static void main(String[] args){
			Request r = new Request();
	}
}
