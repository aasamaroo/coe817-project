
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;

import java.io.*;
public class CTF extends Thread{
    static Map<String, Boolean> validation_list = new HashMap<String, Boolean>();
    static Map<String, Integer> candidate_list = new HashMap<String, Integer>();
    static Map<String, String> voter_list = new HashMap<String, String>();
    static String encodedKey = "TW9ua2U2OQ==";
    static String clientKey = "P3u642U5F2==";
    static boolean lastMessage = false;
    private Socket socket = null;

    public CTF(Socket socket) {
        super("CTF");
        this.socket = socket;
    }

    public void run() {
        try {
            PrintWriter out =
                new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in =
                new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            BufferedReader stdIn =
                new BufferedReader(
                    new InputStreamReader(System.in));
        
            String connectionLine = in.readLine();
            if (connectionLine.equalsIgnoreCase("CLA")) {
                byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
                Cipher decrypt = Cipher.getInstance("DES");
                decrypt.init(Cipher.DECRYPT_MODE, originalKey);
                Cipher encrypt = Cipher.getInstance("DES");
                encrypt.init(Cipher.ENCRYPT_MODE, originalKey);

                if (!candidate_list.containsKey("Cungang")) {
                    candidate_list.put("Cungang", 0);
                    candidate_list.put("Krista", 0);
                    candidate_list.put("William", 0);
                    candidate_list.put("Oscar", 0);
                    candidate_list.put("Alexander", 0);
                }

                String inputLine;
                while ((inputLine = in.readLine()) != null) {

                    if (inputLine.equals("finished")) {
                        lastMessage = true;
                        break;
                    }

                    byte[] decode = Base64.getDecoder().decode(inputLine);
                    byte[] decrypted = decrypt.doFinal(decode);
                    String[] splitText = new String(decrypted).split("\\|");
                    System.out.println(splitText[0]); //Validation Number
                    if (!validation_list.containsKey(splitText[0])) { //Discard Potential Duplicate Validation Numbers
                        validation_list.put(splitText[0], false);
                    }
                }

            }
            else if (connectionLine.equalsIgnoreCase("Client")) {
                byte[] decodedKey = Base64.getDecoder().decode(clientKey);
                SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
                Cipher decrypt = Cipher.getInstance("DES");
                decrypt.init(Cipher.DECRYPT_MODE, originalKey);
                Cipher encrypt = Cipher.getInstance("DES");
                encrypt.init(Cipher.ENCRYPT_MODE, originalKey);

                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    byte[] decode = Base64.getDecoder().decode(inputLine);
                    byte[] decrypted = decrypt.doFinal(decode);
                    String[] splitText = new String(decrypted).split("\\|");
                    System.out.println(splitText[0]); //Validation Number
                    System.out.println(splitText[1]); //Candidate
                    System.out.println(splitText[2]); //Id

                    if (validation_list.containsKey(splitText[0]) == false && voter_list.containsKey(splitText[2]) == false) {
                        for (Map.Entry<String, Boolean> entry : validation_list.entrySet()) {
                            if (entry.getKey().equals(splitText[0])) {
                                entry.setValue(true);
                                break;
                            }
                        }
                        for (Map.Entry<String, Integer> entry : candidate_list.entrySet()) {
                            if (entry.getKey().equals(splitText[1])) {
                                entry.setValue(entry.getValue() + 1);
                                break;
                            }
                        }
                        voter_list.put(splitText[2], splitText[1]); //Voter id and candidate
                    }
                    
                    if (lastMessage == true)
                        break;
                }
                for (Map.Entry<String, Integer> set : candidate_list.entrySet()) {
                    System.out.println(set.getKey() + " = " + set.getValue());

                    String message = set.getKey() + "|" + set.getValue();
                    byte[] encrypted = encrypt.doFinal(message.getBytes());
                    out.println(Base64.getEncoder().encodeToString(encrypted));
                }
            }

            System.out.println("Done");
            socket.close();
        } catch (Exception e) {
            System.out.println("Exception caught when trying to listen");
            System.out.println(e.getMessage());
        }
    }
}
