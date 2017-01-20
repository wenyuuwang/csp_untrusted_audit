package frame;

import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.event.*;
import javax.swing.*;

import java.io.*;

import access.*;
import filework.*;


public class TestFrame extends JFrame implements ActionListener {
	
	JFrame user_frame;
	JButton user_confirm, user_cancel, acl_update, blc_update;
	//JTextField hashID_field, idVersion_field, filename_field;
	String hashID, filename;
	int user_ver;
	
	
	public TestFrame(){
		user_frame = new JFrame();
		user_frame.setLayout(new GridLayout(2,2));
		//hashID
		/*JPanel hashID_panel = new JPanel();
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
		user_frame.add(blockID_panel);*/
		//buttons
		user_confirm = new JButton("View");
		user_cancel = new JButton("Cancel");
		acl_update = new JButton("ACL");
		blc_update = new JButton("Block");
		user_frame.add(user_confirm);
		user_frame.add(user_cancel);
		user_frame.add(acl_update);
		user_frame.add(blc_update);
		user_confirm.addActionListener(this);
		user_cancel.addActionListener(this);
		acl_update.addActionListener(this);
		blc_update.addActionListener(this);
		
		//set frame size
		user_frame.setResizable(false);
		user_frame.setVisible(true);		
		int w = (Toolkit.getDefaultToolkit().getScreenSize().width - 300) / 2;
		int h = (Toolkit.getDefaultToolkit().getScreenSize().height - 200) / 2;
		user_frame.setLocation(w, h);
		user_frame.setSize(300, 200);
		user_frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	
	/**
	 * CSP read request, conduct authorization and make:
	 * 1.attestation, 2.Permission, 3url.txt
	 * @param hashID
	 * @param BlockID
	 * @param user_ver
	 */
	public void cspWork(String hashID, String BlockID, int user_ver){
		
		Authorization judge = new Authorization();
		User u = new User(hashID);
		u.setVersion(user_ver);
		
		//CSP check user's validity
		boolean valid = judge.isValid(u, filename);
		
		if(valid){
			System.out.println("valid user");
			u.setValid();		
			FileData f = new FileData(filename);
			//******** remove OH for experiment (attestation in distributed v.s. our attestation) **********
			//judge.makeAttest_withOH(u, f);
			long t1 = System.currentTimeMillis();
			int i=2;		
			int loop_size = 1; //to make a number of attestations
			boolean distribute = false;
			String prev_chain = "";
			if(distribute){
				prev_chain = judge.makeDistributeAttest(u, f, i);
				do{
					prev_chain = judge.makeDistributeAttest(u, f, i, prev_chain);
					i ++;
				}while(i<loop_size);
			}else {
				prev_chain = judge.makeAttest(u, f, i);
				do{
					prev_chain = judge.makeAttest(u, f, i, prev_chain);
					i ++;
				}while(i<loop_size);
			}			
			long t2 = System.currentTimeMillis(); 
			System.out.println("程序运行时间： "+(t2-t1)+"ms"); 
			//System.exit(0);		
			u.read(f);	//only url file in this method; still need a method to generate Permission according to Request.				
		}
		else{
			System.out.println("unauthorized");
			JOptionPane.showMessageDialog(null, "Unauthorized ID to view ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
			TestFrame user_frame = new TestFrame();
		  }
	}
	
	
	public static void main(String[] args){
	
		TestFrame user_frame = new TestFrame();	
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		JButton clicked = (JButton)e.getSource();
		if(clicked == user_cancel){		
			user_frame.dispose();
			System.exit(0);
		}else if(clicked == user_confirm){			
			try {
				BufferedReader r = new BufferedReader(new FileReader("request.txt"));
				String content;
				content = r.readLine();
				r.close();
				String[] array_content = content.split("#");
				hashID = array_content[1];
				user_ver = Integer.parseInt(array_content[2].substring(3));
				filename = array_content[3];
				user_frame.dispose();
				cspWork(hashID, filename, user_ver);	
			} catch (IOException e1) {
				e1.printStackTrace();
			}					
		}else if(clicked == acl_update){
			//Group dynamics
			//name: filename of new ACL
			//notice: this branch has not been tested after changes of code in this project. It may encounter errors. 
			String name = "valid_user_add1000_en.txt";
			long t1, t2; 
				t1 = System.currentTimeMillis();
				if(VerifySig.verifyInnerSig(name)){
					ModifyJar mj = new ModifyJar();
					mj.updateJarFile(name, null, null);
					t2 = System.currentTimeMillis(); 
					System.out.println("["+name+"]程序运行时间： "+(t2-t1)+"ms"); 	
					JOptionPane.showMessageDialog(null, "New ACL made ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
					System.exit(0);
				}else{
					JOptionPane.showMessageDialog(null, "Unauthorized sig on list ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
				}			
		}else if(clicked == blc_update){
			//Data dynamics
			//BlockID : block to be updated, use # to separate more than 1 blocks
			//notice: this branch has not been tested after changes of code in this project. It may encounter errors. 
			String blockIDs = JOptionPane.showInputDialog(null, "BlockID:");
			long t1, t2; 
			t1 = System.currentTimeMillis();
			String[] array_blockid = blockIDs.split("#");
			StringBuilder array_blockHash = new StringBuilder();
			for(int i=0; i<array_blockid.length; i++ ){
				if(VerifySig.verifyInnerSig(array_blockid[i])){
					Block newContent = new Block(array_blockid[i]);
					//record the hash of blocks to be modified
					array_blockHash.append(newContent.updateBlock()+"#");
					JOptionPane.showMessageDialog(null, "New block made ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
					System.exit(0);
				}else{
					JOptionPane.showMessageDialog(null, "Unauthorized sig on file ", "Message",JOptionPane.INFORMATION_MESSAGE, null);
				}
			}
			ModifyJar mj = new ModifyJar();
			mj.updateJarFile("blockID.txt", blockIDs, array_blockHash.toString());
			t2 = System.currentTimeMillis(); 
			System.out.println("["+array_blockid.length+"]程序运行时间： "+(t2-t1)+"ms"); 	
			System.exit(0);
			
		}
	}
}
