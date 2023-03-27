
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
public class CTF {
    public static void main(String[] args) throws IOException {
        try (
            ServerSocket serverSocket =
                new ServerSocket(9090, 0, InetAddress.getLoopbackAddress());
            Socket clientSocket = serverSocket.accept();     
            PrintWriter out =
                new PrintWriter(clientSocket.getOutputStream(), true);                   
            BufferedReader in = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream()));
        ) {
            
            ArrayList<String> validation_list = new ArrayList();
            Map<String, Integer> candidate_list = new HashMap<String, Integer>();
            candidate_list.put("Cungang", 0);
            candidate_list.put("Krista", 0);
            candidate_list.put("William", 0);
            candidate_list.put("Oscar", 0);
            candidate_list.put("Alexander", 0);

            String encodedKey = "TW9ua2U2OQ==";
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
            Cipher decrypt = Cipher.getInstance("DES");
            decrypt.init(Cipher.DECRYPT_MODE, originalKey);
            Cipher encrypt = Cipher.getInstance("DES");
            encrypt.init(Cipher.ENCRYPT_MODE, originalKey);

            String inputLine;
            while ((inputLine = in.readLine()) != null) {

                if (inputLine.equals("finished"))
                    break;
                
                byte[] decode = Base64.getDecoder().decode(inputLine);
                byte[] decrypted = decrypt.doFinal(decode);
                String[] splitText = new String(decrypted).split("\\|");
                System.out.println(splitText[0]); //Validation Number
                System.out.println(splitText[1]); //Candidate

                if (!validation_list.contains(splitText[0])) { //Disacrd Duplicate Validation Numbers
                    validation_list.add(splitText[0]);
                    for (Map.Entry<String, Integer> entry : candidate_list.entrySet()) {
                        if (entry.getKey().equals(splitText[1])) {
                            entry.setValue(entry.getValue() + 1);
                            break;
                        }
                    }
                }
            }
            for (Map.Entry<String, Integer> set : candidate_list.entrySet()) {
                System.out.println(set.getKey() + " = " + set.getValue());

                String message = set.getKey() + "|" + set.getValue();
                byte[] encrypted = encrypt.doFinal(message.getBytes());
                out.println(Base64.getEncoder().encodeToString(encrypted));
            }
            System.out.println("Done");
        } catch (Exception e) {
            System.out.println("Exception caught when trying to listen");
            System.out.println(e.getMessage());
        }
    }
}
