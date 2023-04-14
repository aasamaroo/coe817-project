import java.security.*;
import java.io.*;
import java.nio.file.*;
import java.text.*;
import java.util.*;
import javax.crypto.*;
import java.net.*;
import java.nio.file.Files;
import java.security.spec.*;
import javax.crypto.spec.*;
import java.time.Instant;
import java.time.Duration;

public class CLA {

    static Cipher enc_cip;
    static Cipher dec_cip;
    private Socket ctfSocket;
    private Socket clientSocket;
    private PrintWriter ctfOut;
    private PrintWriter clientOut;
    private BufferedReader ctfIn;
    private BufferedReader clientIn;
    private String PR_cla = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJGhm+G+6AvIu5TsegW+DskKrqh1nmRTciJVGwHI0ey6X5AavaaPR0fNIVnHnIzghgE44jsgnBejDRrCrQYP2ro86XU05BbgQMBKviFDm1ZVqqHg/kW+T8OVncq+VJ+gEv0lq/SzD6rI6+BtiLrH88F3RFGVv62n6ChX4/R9quDpAgMBAAECgYAIJwSfrsz1KevMUq+jBih0Oy+bWRhAlAZJ4ztDjo8n4igK3GBdBFzQaWySRtEd9syxoVJSzojGbveDFb5TXkxXdmIOIkNTIAMi7cBY7etJefDypeq4A32+mmUOgIfUwGWTYr2d1cmNuz2Cdzpkizl1rlVT+CenaBTy9WMRBp2oQQJBAKwW885gJlUMlDKZaysuk3cKom+ALaNhPN76qZoZ0KJdxovnLCgaQWzc97tHtMcUmWGwbhoC3qX4sTAeVgX2MWECQQDYo/801gHKWkIMKDj2wlEmSvdpKc55ZNRDNl6O2HQWruVkKUJZEyLLAblRSgX6T/FXC/lKU2Lr7iv2hiTiGvSJAkA90JzRE96RDEyrhEpnn3pe91XzwVIjbslDuzxy2zUDLbYlCOvml8/Kf/EIt7ArFq4l1g8mjsNVUOisxSjXSWDhAkBH/WdHFX6O0aN1CsCzLytsQCkrJxtXt6vZke2mJkOdbg0IVbWYiAVd1HrSinimD36xYGc8zaznncO6LiV/hVmRAkEAnz/72UipWBuwuDH5EGpmOnT8ln470sHGzkSL4UpXI5rloc3F68bJTGEsRwyJtwdsy2uvarAF8kaAlXh6DPkkZw==";
    public String PU_cla = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRoZvhvugLyLuU7HoFvg7JCq6odZ5kU3IiVRsByNHsul+QGr2mj0dHzSFZx5yM4IYBOOI7IJwXow0awq0GD9q6POl1NOQW4EDASr4hQ5tWVaqh4P5Fvk/DlZ3KvlSfoBL9Jav0sw+qyOvgbYi6x/PBd0RRlb+tp+goV+P0farg6QIDAQAB";
    private String PU_client = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqHG0CsktS7D3wuYGMbBWbM+iK7sHiMiM+VvnrgsYc3qhGU52UtjtgGPt4oxdkcM5jGFWgbGoNi+NT29JiugkLihx3MJw3RsKvFLiakvkNzr/7xH3wKkQN0FwZVpY0SfIuN4Q4nRAkKWDIxB+9vGBBXFCUmKY1w9yHEOfD8TfxJwIDAQAB";


    private static final File file = new File(System.getProperty("user.dir") + "/coe817-project/CLA.txt");
    private static Scanner s;

    private static final ArrayList<String> voters = new ArrayList<>();
    private static final ArrayList<String> names = new ArrayList<>();
    private static final ArrayList<Integer> sin = new ArrayList<>();

    private static String firstName, lastName, sinID;

    private static Integer sinNum;

    public CLA() throws Exception {
         enc_cip = Cipher.getInstance("RSA");
         dec_cip = Cipher.getInstance("RSA");
     }


    public String encrypt(String toEncode) throws Exception {

        PublicKey publicKey = loadPublicKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(toEncode.getBytes());
        return new String(Base64.getEncoder().encode(bytes));
    }

    public String encryptWithClientPub(String toEncode) throws Exception {

        PublicKey publicKey = loadClientPublicKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(toEncode.getBytes());
        return new String(Base64.getEncoder().encode(bytes));
        }

    public String decrypt(String toDecode) throws Exception {

        PrivateKey privateKey = loadPrivateKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(toDecode));
        return new String(bytes);

        }

    public String encryptWithSharedKey(String input, String sharedKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
        InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {

        byte[] encodedKey = Base64.getDecoder().decode(sharedKey);
        SecretKey key = new SecretKeySpec(encodedKey, "DES");

        //IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
		return new String(Base64.getEncoder().encode(cipherText));	
    }

    public String decryptWithSharedKey(String input, String sharedKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {

        byte[] encodedKey = Base64.getDecoder().decode(sharedKey);
        SecretKey key = new SecretKeySpec(encodedKey, "DES");

        //IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(Base64.getDecoder().decode(input.getBytes()));
        return new String(cipherText);
    }


    public static void returnLine() throws FileNotFoundException {

        s = new Scanner(file);
        ArrayList<String> lines = new ArrayList<>();

        while (s.hasNext()) {
            try {
                firstName = s.next();
                lastName = s.next();
                sinID = s.next();
            } catch (Exception e) {
                break;
            }
            if (isInt(sinID)) {
                sinNum = Integer.valueOf(sinID);
            }

            names.add(firstName);
            sin.add(sinNum);
            lines.add(firstName + " " + lastName + " " + sinNum);
        }
        voters.addAll(lines);

    }

    private static boolean isInt(String s) {
        try {
            int d = Integer.valueOf(s);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }

    }

    //return random validation number
    private static String generateVerfication() {
        String x = UUID.randomUUID().toString();
        return x;
    }

    public static void addToFile(String info) throws IOException {
        File file = new File(System.getProperty("user.dir") + "/coe817-project/CLA.txt");
        Scanner sc = new Scanner(file);
        ArrayList<String> lines = new ArrayList<>();
        while (sc.hasNext()) {
            lines.add(sc.nextLine());
        }
        sc.close();
        FileWriter writer = new FileWriter(file);
        for (String s : lines) {

            writer.write(s + "\n");
        }
        writer.write(info + "\n");
        writer.close();
    }

    public String generateKeyToDistribute() throws NoSuchAlgorithmException {
        // Generate cryptographic key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");

        SecretKey secretKey = keyGenerator.generateKey();

        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());;

        return encodedKey;

    }

    private PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(PU_cla));
        PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
        return publicKey;
        }

        private PublicKey loadClientPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

            KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(PU_client));
            PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
            return publicKey;
         }


        private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
			
            KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PR_cla));
            PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
            return privateKey;
            }

        public String signMessage(String messageToSign) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
            PrivateKey privateKey = loadPrivateKey();

            //MessageDigest md = MessageDigest.getInstance("SHA-256");
            //byte[] messageDigest = md.digest(messageToSign.getBytes());
        // Encrypt the message digest with the private key to create the digital signature
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initSign(privateKey);
            signature.update(messageToSign.getBytes());
            byte[] digitalSignature = signature.sign();

        // Convert the digital signature to a base64-encoded string for easy representation
        String base64DigitalSignature = Base64.getEncoder().encodeToString(digitalSignature);

        // Attach the digital signature to the original data as needed
        String digitallySignedData = messageToSign + "|" + base64DigitalSignature;

        return digitallySignedData;

        }

    public static void main(String[] args) {
        int portNumber = 6969;
        int portNumberServer = 9090;
        try {
            CLA x = new CLA();
            // x.PR_cla = x.loadPrivateKey();
            // x.PU_cla = x.loadPublicKey();

            while (true) {
                try {

                    //connect to CTF
                    x.ctfSocket = new Socket("localhost", portNumberServer);
                    x.ctfOut = new PrintWriter(x.ctfSocket.getOutputStream(), true);
                    x.ctfIn = new BufferedReader(new InputStreamReader(x.ctfSocket.getInputStream())); //Might need this for acknowledgement
                    //Test
                    //x.ctfOut.println("CLA");

                    //connect to Client
                    ServerSocket client = new ServerSocket(portNumber);
                    x.clientSocket = client.accept();
                    x.clientOut = new PrintWriter(x.clientSocket.getOutputStream(), true);
                    x.clientIn = new BufferedReader(new InputStreamReader(x.clientSocket.getInputStream()));

                    //wait for voter to request validation number
                    String inputLine;
                    System.out.println("Waiting for messages");

                    while (true) {

                        inputLine = x.clientIn.readLine();
						System.out.println("Input = " + inputLine);

                        if (inputLine != null) {
                            //Message 1
                            String input = x.decrypt(inputLine);
                            System.out.println("Message 1 received :" + input);

                            //Read Nonce1 from Client
                            String[] parts = input.split("\\|");
                            String receivedNonce1 = parts[0];

                            //Create Nonce2 and send it along with Nonce1 to client to confirm identity
                            //Meesage 2
                            SecureRandom secureRandom = new SecureRandom();
                            int nonce2 = secureRandom.nextInt();
							System.out.println("Generate nonce 2 = " + nonce2);
                            String replyToClient = receivedNonce1 + "|" + nonce2;
                            String encodedReply = x.encryptWithClientPub(replyToClient);
							System.out.println(encodedReply);
                            x.clientOut.println(encodedReply);

                            //Message 3
                            String input2 = x.clientIn.readLine();
                            input2 = x.decrypt(input2);
                            System.out.println("Message 3 received: " + input2);
                            //Check if nonce matches up
                            if(!input2.equals(Integer.toString(nonce2))){
                                break;
                            }


                            //Once we confirm the user, we can send out the session key
                            String sessionKey = x.generateKeyToDistribute();
                            Instant t1 = Instant.now();
                            String sendSessionKey = sessionKey + "|" + t1;
                            String signedSessionKeyMsg = x.signMessage(sendSessionKey);
							System.out.println("Message + signature = " + signedSessionKeyMsg);
                            String sessionKeyMessage = x.encryptWithClientPub(sendSessionKey);
							//Message 4
                            x.clientOut.println(sessionKeyMessage);
							
                            //Message 6
                            String input3 = x.clientIn.readLine();
                            input3 = x.decryptWithSharedKey(input3,sessionKey);
                            if (voters.contains(input3)) //Do not allow duplicate voters
                                break;
                            voters.add((input3));
                            //names.add((input)); Not sure what the client message format is
                            //sin.add((input)); Not sure what the client message format is


                            //create validation number for voter and send to them
                            String vc = generateVerfication();

                            //save new validation number to list
                            //CLA.addToFile(input + " " + vc);

                            //Create TimeStamp
                            Instant t3 = Instant.now();
                            String sendVerificationNumber = vc + "|" + t3;
                            //Send verification number to CTF and client
                            String encryptedOut = x.encryptWithSharedKey(sendVerificationNumber,sessionKey);
                             //Message 7
                            x.ctfOut.println("CLA"); //Send identity first
                            x.ctfOut.println(encryptedOut);
                            x.clientOut.println(encryptedOut);
                            System.out.println("vc sent:" + vc);
                            break;
                        } else {
                            System.out.println("null");
                        }
                    }

                    System.out.println("Done.\n");
                    x.clientOut.close();
                    x.clientIn.close();
                    x.ctfOut.close();
                    x.ctfIn.close();
                    client.close();
                    System.out.println("Done.\n");

                } catch (Exception e) {
					System.out.println(e);
					e.printStackTrace();
                    x.ctfOut.close();
                    x.ctfIn.close();
                    x.clientOut.close();
                    x.clientIn.close();
                    System.out.println("Connection lost, closing connection.");
					break;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

