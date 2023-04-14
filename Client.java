/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

//package coe817project;

import java.awt.event.*;
import java.awt.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.time.*;
import java.net.*;
import java.util.*;
import javax.swing.*;
import java.nio.file.*;
import java.text.*;

/**
 *
 * @author j1tian
 */
public class Client extends JFrame {
    
    JFrame frame = new JFrame("Voting Portal");
    JPanel container = new JPanel();
    JPanel loginPanel  = new JPanel();
    JPanel votingPanel = new JPanel();
    JPanel resultsPanel = new JPanel();
    JButton login = new JButton("Login");
    JButton vote = new JButton("Submit Vote");
    CardLayout cl = new CardLayout();
	private static String sharedKey;
    private static String validationNum;
    private static String candidate;
	private static Socket sockCla;
	private static PrintWriter outCla; 
	private static BufferedReader inCla;
	
	private static Socket sockCtf;
	private static PrintWriter outCtf; 
	private static BufferedReader inCtf;

	static PublicKey publicKeyCLA = null;
    static PublicKey publicKeyCTF = null;
    static PrivateKey privateKey = null;

	static String publicKeyStringCLA = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRoZvhvugLyLuU7HoFvg7JCq6odZ5kU3IiVRsByNHsul+QGr2mj0dHzSFZx5yM4IYBOOI7IJwXow0awq0GD9q6POl1NOQW4EDASr4hQ5tWVaqh4P5Fvk/DlZ3KvlSfoBL9Jav0sw+qyOvgbYi6x/PBd0RRlb+tp+goV+P0farg6QIDAQAB";
    static String publicKeyStringCTF =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxnJXfl0iqJAWvaM2jNvSa58TRePoaz7J3PMi9pXcdbe6yJRMXFku6k4k7OD3OgKU6pOAOvjeUZK8vJXh/MqOWWCUuwQ3y39fon2xF0etSQEx95qtrYYp5QPJyz2UIfJzFLZKG/WxQJcxWIQToTR3WuSACmA7FgGK5Kfk8qgDUNwIDAQAB";
    static String publicKeyStringClient = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqHG0CsktS7D3wuYGMbBWbM+iK7sHiMiM+VvnrgsYc3qhGU52UtjtgGPt4oxdkcM5jGFWgbGoNi+NT29JiugkLihx3MJw3RsKvFLiakvkNzr/7xH3wKkQN0FwZVpY0SfIuN4Q4nRAkKWDIxB+9vGBBXFCUmKY1w9yHEOfD8TfxJwIDAQAB";
	static String privateKeyStringClient = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKocbQKyS1LsPfC5gYxsFZsz6IruweIyIz5W+euCxhzeqEZTnZS2O2AY+3ijF2RwzmMYVaBsag2L41Pb0mK6CQuKHHcwnDdGwq8UuJqS+Q3Ov/vEffAqRA3QXBlWljRJ8i43hDidECQpYMjEH728YEFcUJSYpjXD3IcQ58PxN/EnAgMBAAECgYBAfX1QR+KpgblrwRAdeb5pM/EldqWXSNW2pQejYtUTjc/ytXFotvtkj6QKVJ4iLGf6Bngz1NYR46YfnRcx6YBSuczR3qQxuSMtQWxVqDQskYCN2sYrJ9t0te0zfr0weuiFY9l0OdObFTkAd0chGSSkDIPEf7u9rG7BUWpsyMOdzQJBALmZz9dJD6DfjthWV3cELpw0JX4SiK4tECN8QpFF6I4c8K6LMGrPzhLQYZA7VMS/ygs7fl1XgMnQPdfkifcHXtUCQQDqoobA7ssWLtAL5iIHYxEfQamNwb6fZjxdM7zJFoqdtcz/55JYWIJ3xKFqZH28mDdMYsLO1UDY7XRwkUlOpmYLAkEAnx/cLfuZxpdk5N3Bx2xyecHLkzdYr9w6xfG3MM37ADyXrU3wiOL5DvBRdVMo7jZwhwjO4kAvTteW7g4mqwBKsQJBAOBEQorMc98bFY4aBHKNFUOL7nVpNzuCa7YmCo8l9Y4yw+PhwraguuuhTSu1K52E3G4tg8hQevAdXwttQuVjFOsCQB0c5Zm7stigRm/MklNQfOCBLKZDjaGNRoyYkOCIxq/RZEYLA5UD4GucZPNi2xDuf0H71HVBmlq+g7bH3g5cHpQ=";
	
	
	
    public Client() throws Exception{
			// to CLA
            sockCla = new Socket("localhost",6969); 
            outCla = new PrintWriter(sockCla.getOutputStream(), true); 
            inCla = new BufferedReader(new InputStreamReader(sockCla.getInputStream()));
			// to CTF
            sockCtf = new Socket("localhost",9090); 
            outCtf = new PrintWriter(sockCtf.getOutputStream(), true); 
            inCtf = new BufferedReader(new InputStreamReader(sockCtf.getInputStream()));
			

		    // change this list to read from a file
		    ArrayList<String> voters = new ArrayList<>();
		    
		    voters.add("12345");
		    voters.add("54321");
		    
		    container.setLayout(cl);
		    JLabel fname_label = new JLabel("Enter First Name");
		    JTextArea fname = new JTextArea("", 1, 20);
		    JLabel lname_label = new JLabel("Enter Last Name");
		    JTextArea lname = new JTextArea("", 1, 20);
		    JLabel sin_label = new JLabel("Enter SIN Number");
		    JTextArea sin = new JTextArea("", 1, 20);
		    
		    loginPanel.add(fname_label);
		    loginPanel.add(fname);
		    loginPanel.add(lname_label);
		    loginPanel.add(lname);
		    loginPanel.add(sin_label);
		    loginPanel.add(sin);
		    
		    loginPanel.add(login);
		    
		    JLabel candidates_label = new JLabel("Please Select a Candidate to Vote For:");
		    
		    JRadioButton r1 = new JRadioButton("Alexander");
		    JRadioButton r2 = new JRadioButton("Oscar");
		    JRadioButton r3 = new JRadioButton("William");
		    JRadioButton r4 = new JRadioButton("Krista");
		    JRadioButton r5 = new JRadioButton("Cunggang");
		    
		    ButtonGroup bg = new ButtonGroup();
		    
		    bg.add(r1);
		    bg.add(r2);
		    bg.add(r3);
		    bg.add(r4);
		    bg.add(r5);
		    
		    votingPanel.add(candidates_label);
		    votingPanel.add(r1);
		    votingPanel.add(r2);
		    votingPanel.add(r3);
		    votingPanel.add(r4);
		    votingPanel.add(r5);

		    votingPanel.add(vote);
		    votingPanel.setLayout(new BoxLayout(votingPanel, BoxLayout.Y_AXIS));
		    
		    container.add(loginPanel, "1");
		    container.add(votingPanel, "2");
		    cl.show(container, "1");
		    
		    login.addActionListener(new ActionListener () {
		        @Override
		        public void actionPerformed(ActionEvent arg0){
					try{
				        System.out.println(fname.getText());
			            String fromServer;

			            KeyFactory kf = KeyFactory.getInstance("RSA");
						// create cla public key cipher 
						X509EncodedKeySpec X509publicKeyCla = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStringCLA));
			        	publicKeyCLA = kf.generatePublic(X509publicKeyCla);
						Cipher cipherEncryptClaPub = Cipher.getInstance("RSA");
			        	cipherEncryptClaPub.init(Cipher.ENCRYPT_MODE, publicKeyCLA);

						// create ctf public key cipher
						X509EncodedKeySpec X509publicKeyCtf = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStringCTF));
			        	publicKeyCTF = kf.generatePublic(X509publicKeyCtf);
						Cipher cipherEncryptCtfPub = Cipher.getInstance("RSA");
			        	cipherEncryptCtfPub.init(Cipher.ENCRYPT_MODE, publicKeyCTF);

						// create client private key cipher
			        	PKCS8EncodedKeySpec X509priv = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStringClient));
			        	privateKey = kf.generatePrivate(X509priv);
				
						Cipher cipherDecryptClientPriv = Cipher.getInstance("RSA");
			        	cipherDecryptClientPriv.init(Cipher.DECRYPT_MODE, privateKey);

						// send message 1 E(KpuCla,nonce1)

			            SecureRandom secureRandom = new SecureRandom();
						int nonce1 = secureRandom.nextInt();
						String message1 = nonce1+"";
						System.out.println("Message 1 = " + message1);
						String message1Encrpyted = rsaEncryptMessage(message1,cipherEncryptClaPub);					
						outCla.println(message1Encrpyted);

						// recieve message 2 E(KpuClient,nonce1|nonce2)
						String message2 = inCla.readLine();
						String message2Decrypted = rsaDecryptMessage(message2,cipherDecryptClientPriv);
						System.out.println("Message 2 = " + message2Decrypted);
						// decrypt
						String[] parts = message2Decrypted.split("\\|");
				
						// send message 3 E(KpuCla,nonce2)
						String message3 = parts[1];
						System.out.println("Message 3 = " + message3);
						String message3Encrypted = rsaEncryptMessage(message3,cipherEncryptClaPub);
						outCla.println(message3Encrypted);

						// recieve message 4 E(KpuClient,KShared|t1|sig(KprCla,KShared|t1))
						String message4 = inCla.readLine();
						String message4Decrypted = rsaDecryptMessage(message4,cipherDecryptClientPriv);
						System.out.println("Message 4 = " + message4Decrypted);
						// decrypt
						String[] partsMessage4 = message4Decrypted.split("\\|");
						sharedKey = partsMessage4[0];

						// send message 5 to CTF -- basically just forward message 4 -- E(KpuCtf,KShared|t1|sig(KprCla,KShared|t1))
						String message5 = message4Decrypted;
						System.out.println("Message 5 = " + message5);
						String message5EncryptedCTF = rsaEncryptMessage(message4Decrypted,cipherEncryptCtfPub);
						System.out.println("Encrypted message 5 = " + message5EncryptedCTF);
						outCtf.println("Client");
						outCtf.println(message5EncryptedCTF);

						// send message 6 E(KShared, id|t2)				
						String id = sin.getText();
						String t2 = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
						String message6 = id + "|" + t2;
						System.out.println("Message 6 = " + message6);
						String encryptedMessage6 = desEncryptMessage(message6,sharedKey);
						outCla.println(encryptedMessage6);

						// recieve message 7 E(KShared,validationNumber|t3)
						String message7 = inCla.readLine();
						String message7Decrypted = desDecryptMessage(message7,sharedKey);
						System.out.println("Message 7 = " + message7Decrypted);
						String[] partsMessage7 = message7Decrypted.split("\\|");
						validationNum = partsMessage7[0];
				        
				        //JLabel validationNum = new JLabel(fromServer);
				        cl.show(container, "2");
					}catch(Exception e){
						System.out.println(e);
					}
		        }
		    });
		    
		    vote.addActionListener(new ActionListener () {
		        @Override
		        public void actionPerformed(ActionEvent arg0) {
		            try{
				        if (r1.isSelected()) {
				            candidate = r1.getText();
				        } else if (r2.isSelected()) {
				            candidate = r2.getText();
				        } else if (r3.isSelected()) {
				            candidate = r3.getText();
				        } else if (r4.isSelected()) {
				            candidate = r4.getText();
				        } else if (r5.isSelected()) {
				            candidate = r5.getText();
				        } else {
				            candidate = "Cunggang"; // votes for cunggang if no one selected
				        }

				        System.out.println(candidate + " " + sin.getText());



			            String fromServer;
			            
			            if (!voters.isEmpty()) {

			                System.out.println("Sending to CTF: " + validationNum + "|" + candidate + "|" + sin.getText());
			                // encrypt and encode this entire string before writing
							// send message 8 E(KShared,validationNumber|Candidate|t4)
						    Instant t1 = Instant.now();
							String message8 = validationNum + "|" + candidate + "|" + sin.getText() + "|" + t1;
							System.out.println("Message 8 = " + message8);
							String encryptedMessage8 = desEncryptMessage(message8,sharedKey);
			                outCtf.println(encryptedMessage8);

			                // if voter is in list, remove them
			                if(voters.contains(sin.getText())) {
			                    voters.remove(sin.getText());
			                }
			            } else {
							// send message 9 E(KShared,"Finished")
							String message9 = "Finished";
							System.out.println("Message 9 = " + message9);
							String encryptedMessage9 = desEncryptMessage(message9,sharedKey);
			                outCtf.println(encryptedMessage9);
					
			                // recieve message 10 E(KShared,results)
			                String message10 = inCtf.readLine();
							// decrypt
							String decryptedMessage10 = desDecryptMessage(message10,sharedKey);
							System.out.println("Message 10 = " + decryptedMessage10);
			                
			                String[] splitResults = decryptedMessage10.split("\\|");
			                for (int i = 0; i < splitResults.length; i++) {
			                    if (i % 2 == 0) {
			                        // tally
			                        JLabel tally = new JLabel(splitResults[i]);
			                        resultsPanel.add(tally);
			                    } else {
			                        // candidates
			                        JLabel candidate = new JLabel(splitResults[i]);
			                        resultsPanel.add(candidate);
			                    }
			                }
			                
			                container.add(resultsPanel, "3");
			                cl.show(container, "3");
			            }
					}catch(Exception e){
						System.out.println(e);
						e.printStackTrace();
					}
		        }
		    });
		    
		    frame.add(container);
		    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		    frame.setSize(300, 300);
		    frame.setVisible(true);

    }

    public static void main(String[] args) {
		try{
        	Client client = new Client();
		}catch(Exception e){
			System.out.println(e);
		}    
	}
	
	private static String desEncryptMessage(String message, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return new String(Base64.getEncoder().encode(encryptedBytes));
    }

    private static String desDecryptMessage(String message, String key) throws Exception{
        byte[] keyBytes = Base64.getDecoder().decode(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DES");
		Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message.getBytes()));
        return new String(decryptedBytes);
    }

	private static String rsaEncryptMessage(String message, Cipher cipher) throws Exception{
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return new String(Base64.getEncoder().encode(encryptedBytes));
    }

    private static String rsaDecryptMessage(String message, Cipher cipher) throws Exception {
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message.getBytes()));
        return new String(decryptedBytes);
    }
}

