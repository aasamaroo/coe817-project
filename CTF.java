
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
import java.time.Duration;

import java.io.*;
public class CTF extends Thread{
    static Map<String, Boolean> validation_list = new HashMap<String, Boolean>();
    static Map<String, Integer> candidate_list = new HashMap<String, Integer>();
    static Map<String, String> voter_list = new HashMap<String, String>();
    static PublicKey publicKeyCTF = null;
    static PublicKey publicKeyCLA = null;
    static PublicKey publicKeyClient = null;
    static PrivateKey privateKey = null;
    static String privatekeyString = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALGcld+XSKokBa9ozaM29JrnxNF4+hrPsnc8yL2ldx1t7rIlExcWS7qTiTs4Pc6ApTqk4A6+N5Rkry8leH8yo5ZYJS7BDfLf1+ifbEXR61JATH3mq2thinlA8nLPZQh8nMUtkob9bFAlzFYhBOhNHda5IAKYDsWAYrkp+TyqANQ3AgMBAAECgYAPA5GXyQ4Xc9wXK+DWPzsGLTlyC6v4wD3x3m2JuocLMdPPs1qdxQC50Ob03pg68J0HDBD0rhe8r5YvghdhiUJSuxZSZ5A5Xbay4HmxwKypeIRy40C6Ih5+XviIUAT9skpqXYG0ehXo+VHRlDw3n0IDhszhMAf6PRTikWWcynr+AQJBAORGT4lCuLHTolncJ6AlnWMfKygUXHBHb3jQdM9I1ak+hC5SNowI7oVyCctziJ9BDeReDGazikFxMprk1qDhYUECQQDHLwXDCjbDXMjOIaq/D7ordZ9H8THuFzWFRbLuTjXQ9cpVwH/0sokISYdjKa+88YrfdZ/U4j4ngnRW4XeXRd93AkEAtz+CJcv7/DTKRZyn6rWHbMTeniQKOM//ulqNCsGLU3uuHIk+5Jde8p0jI8GxUTal8kdVaTSDrhky6Ij/itKigQJAPp7t9M+1P95f006KW98Z7KfiF8AgrnXlgazUAE/eY3+iySroD4pBwrU7N1XXxlM6Ed7tDQTD/a/p25au/oQdKQJBAIivEdWH8IU4mA7FYB88Kouygqpe6tYJMRmUzizVSBT3yrfWo1Yzvfm0peBldjFyjgG8WBfKXZgZav9f3FeeCn0=";
    static String publicstringCTF =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxnJXfl0iqJAWvaM2jNvSa58TRePoaz7J3PMi9pXcdbe6yJRMXFku6k4k7OD3OgKU6pOAOvjeUZK8vJXh/MqOWWCUuwQ3y39fon2xF0etSQEx95qtrYYp5QPJyz2UIfJzFLZKG/WxQJcxWIQToTR3WuSACmA7FgGK5Kfk8qgDUNwIDAQAB";
    static String pubkeystringClient = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqHG0CsktS7D3wuYGMbBWbM+iK7sHiMiM+VvnrgsYc3qhGU52UtjtgGPt4oxdkcM5jGFWgbGoNi+NT29JiugkLihx3MJw3RsKvFLiakvkNzr/7xH3wKkQN0FwZVpY0SfIuN4Q4nRAkKWDIxB+9vGBBXFCUmKY1w9yHEOfD8TfxJwIDAQAB";
    static String pubkeystringCLA = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRoZvhvugLyLuU7HoFvg7JCq6odZ5kU3IiVRsByNHsul+QGr2mj0dHzSFZx5yM4IYBOOI7IJwXow0awq0GD9q6POl1NOQW4EDASr4hQ5tWVaqh4P5Fvk/DlZ3KvlSfoBL9Jav0sw+qyOvgbYi6x/PBd0RRlb+tp+goV+P0farg6QIDAQAB";        
    static String sharedKey = null;
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
        
            String connectionLine;
            while ((connectionLine = in.readLine()) != null) {
                System.out.println(connectionLine);
                if (connectionLine.equalsIgnoreCase("CLA")) {
                    while (sharedKey == null) {
                      Thread.sleep(500);
                    }
                    System.out.println("Shared key = " + sharedKey);

                    byte[] decodedKey = Base64.getDecoder().decode(sharedKey);
                    SecretKey originalKey = new SecretKeySpec(decodedKey, "DES");
                    Cipher decrypt = Cipher.getInstance("DES");

                    decrypt.init(Cipher.DECRYPT_MODE, originalKey);
                    Cipher encrypt = Cipher.getInstance("DES");
                    encrypt.init(Cipher.ENCRYPT_MODE, originalKey);

                    if (!candidate_list.containsKey("Cunggang")) {
                        candidate_list.put("Cunggang", 0);
                        candidate_list.put("Krista", 0);
                        candidate_list.put("William", 0);
                        candidate_list.put("Oscar", 0);
                        candidate_list.put("Alexander", 0);
                    }

                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {

                        byte[] decode = Base64.getDecoder().decode(inputLine);
                        byte[] decrypted = decrypt.doFinal(decode);
                        String[] splitText = new String(decrypted).split("\\|");
                        System.out.println("Validation number from CLA = " + splitText[0]); //Validation Number
                        System.out.println("Timestamp from CLA = " + splitText[1]); //Time stamp

                        Instant instant = Instant.parse(splitText[1]);
                        Instant now = Instant.now();
                        Duration dur = Duration.between(now, instant);
                        if (dur.getSeconds() < 1)
                            System.out.println("Valid time");

                        if (!validation_list.containsKey(splitText[0])) { //Discard Potential Duplicate Validation Numbers
                            validation_list.put(splitText[0], false);
                        }
                    }

                }
                else if (connectionLine.equalsIgnoreCase("Client")) {
                    String keyExchange = in.readLine();
                    System.out.println("From client = " + keyExchange);

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PKCS8EncodedKeySpec X509priv = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privatekeyString));
                    privateKey = kf.generatePrivate(X509priv);

                    X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(Base64.getDecoder().decode(pubkeystringCLA));
                    publicKeyCLA = kf.generatePublic(X509publicKey);

                    X509EncodedKeySpec X509pub = new X509EncodedKeySpec(Base64.getDecoder().decode(pubkeystringClient));
                    publicKeyClient = kf.generatePublic(X509pub); 

                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    
                    System.out.println("pub/priv keys made");
                    String[] splitKeyExchange = keyExchange.split("\\|");
                    byte[] decrypta = cipher.doFinal(Base64.getDecoder().decode(splitKeyExchange[0].getBytes()));
                    keyExchange = new String(decrypta);
                    System.out.println("decrypted values = " + keyExchange);
                    String[] values = keyExchange.split("\\|");
                    sharedKey = values[0];
                    System.out.println("Shared key = " + sharedKey);
                    String time = values[1];
                    String signature = splitKeyExchange[1];
					System.out.println("Digital signature = "+  signature);
                    
                    //Verify timestamp
                    Instant instant = Instant.parse(time);
                    Instant now = Instant.now();
                    Duration dur = Duration.between(now, instant);
                    if (dur.getSeconds() < 1)
                        System.out.println("Valid time");

                    //Verify Signature
                    
                    Signature sr = Signature.getInstance("SHA1WithRSA");
                    sr.initVerify(publicKeyCLA);
                    sr.update((sharedKey + "|" + time).getBytes());
                    if (sr.verify(Base64.getDecoder().decode(splitKeyExchange[1]))) {
                        System.out.println("Verified");
                    } else {
                        System.out.println("Not Valid");
                    }
                    
                    //Instantiate encrypter and decrypter shared key
                    byte[] keyBytes = Base64.getDecoder().decode(sharedKey);
                    SecretKey secretKey = new SecretKeySpec(keyBytes, "DES");
                    Cipher decrypt = Cipher.getInstance("DES");
                    decrypt.init(Cipher.DECRYPT_MODE, secretKey);
                    Cipher encrypt = Cipher.getInstance("DES");
                    encrypt.init(Cipher.ENCRYPT_MODE, secretKey);

                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        System.out.println("Voting message: " + inputLine);
                        byte[] decode = Base64.getDecoder().decode(inputLine);
                        byte[] decrypted = decrypt.doFinal(decode);
                        
                        String[] splitText = new String(decrypted).split("\\|");

                        //Break on finished message
                        if (splitText[0].equalsIgnoreCase("finished")) {
                            lastMessage = true;
                            break;
                        }

                        System.out.println(splitText[0]); //Validation Number
                        System.out.println(splitText[1]); //Candidate
                        System.out.println(splitText[2]); //Id
                        System.out.println(splitText[3]); //Time stamp

                        instant = Instant.parse(splitText[3]);
                        dur = Duration.between(now, instant);
                        if (dur.getSeconds() < 1)
                            System.out.println("Valid time");

                        if (validation_list.containsKey(splitText[0]) && voter_list.containsKey(splitText[2]) == false) {
                            for (Map.Entry<String, Boolean> entry : validation_list.entrySet()) {
                                if (entry.getKey().equalsIgnoreCase(splitText[0])) {
                                    entry.setValue(true);
                                    break;
                                }
                            }
                            for (Map.Entry<String, Integer> entry : candidate_list.entrySet()) {
                                if (entry.getKey().equalsIgnoreCase(splitText[1])) {
                                    entry.setValue(entry.getValue() + 1);
                                    break;
                                }
                            }
                            voter_list.put(splitText[2], splitText[1]); //Voter id and candidate
                        }
                        sharedKey = null;
                        for (Map.Entry<String, Integer> set : candidate_list.entrySet()) {
                            System.out.println(set.getKey() + " = " + set.getValue());
                        }
                    }
                    String output = null;
                    for (Map.Entry<String, Integer> set : candidate_list.entrySet()) {
                        System.out.println(set.getKey() + " = " + set.getValue());

                        String message = set.getKey() + "|" + set.getValue();

                        if (output == null)
                            output = message;
                        else 
                            output += "|" + message;

                    }
                    byte[] encrypted = encrypt.doFinal(output.getBytes());
                    out.println(Base64.getEncoder().encodeToString(encrypted)); //Sends results to client
                }
                break;
            }

            System.out.println("Done");
            socket.close();
        } catch (Exception e) {
            System.out.println("Exception caught when trying to listen");
            System.out.println(e.getMessage());
			e.printStackTrace();
        }
    }
}


