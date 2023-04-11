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


public class CLA {

    static Cipher enc_cip;
    static Cipher dec_cip;
    private Socket ctfSocket;
    private Socket clientSocket;
    private PrintWriter ctfOut;
    private PrintWriter clientOut;
    private BufferedReader ctfIn;
    private BufferedReader clientIn;
    private String PR_cla;
    public String PU_cla;
    private String PU_client;


    private static final File file = new File(System.getProperty("user.dir") + "\\coe817-project\\CLA.txt");
    private static Scanner s;

    private static final ArrayList<String> voters = new ArrayList<>();
    private static final ArrayList<String> names = new ArrayList<>();
    private static final ArrayList<Integer> sin = new ArrayList<>();

    private static String firstName, lastName, sinID;

    private static Integer sinNum;

    public CLA() throws Exception {
         enc_cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         dec_cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
     }


    public String encrypt(String toEncode) throws Exception {

        PublicKey publicKey = loadPublicKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(toEncode.getBytes("StandardCharsets.UTF_8"));
        return new String(Base64.getEncoder().encode(bytes));
    }

    public String encryptWithClientPub(String toEncode) throws Exception {

        PublicKey publicKey = loadClientPublicKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(toEncode.getBytes("StandardCharsets.UTF_8"));
        return new String(Base64.getEncoder().encode(bytes));
        }

    public String decrypt(String toDecode) throws Exception {

        PrivateKey privateKey = loadPrivateKey();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(Base64.getDecoder().decode(toDecode));
        return new String(bytes);

        }

    public String encryptWithSharedKey(String input) throws NoSuchPaddingException, NoSuchAlgorithmException,
        InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {

        byte[] encodedKey = generateKeyToDistribute();
        SecretKey key = new SecretKeySpec(encodedKey, "AES");

        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
            .encodeToString(cipherText);
    }

    public String decryptWithSharedKey(String input) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {


        byte[] encodedKey = generateKeyToDistribute();
        SecretKey key = new SecretKeySpec(encodedKey, "AES");

        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return new String(Base64.getDecoder()
            .decode(cipherText));

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
        File file = new File(System.getProperty("user.dir") + "\\coe817-project\\CLA.txt");
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

    public byte[] generateKeyToDistribute() throws NoSuchAlgorithmException {
        // Generate cryptographic key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        SecretKey secretKey = keyGenerator.generateKey();

        byte[] encodedKey = secretKey.getEncoded();

        return encodedKey;

    }

    private PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // reading from resource folder
        byte[] publicKeyBytes = getClass().getResourceAsStream("/CLA.pub").readAllBytes();

        KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
        return publicKey;
        }

        private PublicKey loadClientPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

            // reading from resource folder
            byte[] publicKeyBytes = PU_client.getBytes();

            KeyFactory publicKeyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = publicKeyFactory.generatePublic(publicKeySpec);
            return publicKey;
            }


        private PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

            // reading from resource folder
            byte[] privateKeyBytes = PR_cla.getBytes();

            KeyFactory privateKeyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = privateKeyFactory.generatePrivate(privateKeySpec);
            return privateKey;
            }

        public String signMessage(String messageToSign) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException{
            PrivateKey privateKey = loadPrivateKey();

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest = md.digest(messageToSign.getBytes());
        // Encrypt the message digest with the private key to create the digital signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(messageDigest);
            byte[] digitalSignature = signature.sign();

        // Convert the digital signature to a base64-encoded string for easy representation
        String base64DigitalSignature = Base64.getEncoder().encodeToString(digitalSignature);

        // Attach the digital signature to the original data as needed
        String digitallySignedData = messageToSign + "\n" + base64DigitalSignature;

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
                        if (inputLine != null) {
                            String input = x.decrypt(inputLine);
                            System.out.println("Message received :" + input);

                            //Read Nonce1 from Client
                            String[] parts = input.split("|");
                            byte[] receivedNonce1 = parts[0].getBytes();

                            //Create Nonce2 and send it along with Nonce1 to client to confirm identity
                            byte[] nonce2 = new byte[16];
                            SecureRandom secureRandom = new SecureRandom();
                            secureRandom.nextBytes(nonce2);
                            String replyToClient = new String(receivedNonce1) + "|" + new String(nonce2);
                            String encodedReply = x.encryptWithClientPub(replyToClient);
                            x.clientOut.println(encodedReply);

                            String input2 = x.decrypt(inputLine);
                            System.out.print("Message received: " + input2);
                            //Check if nonce matches up
                            if(!input2.equals(nonce2.toString())){
                                break;
                            }

                            //Once we confirm the user, we can send out the session key
                            byte[] sessionKey = x.generateKeyToDistribute();
                            String sessionKeyString = new String(sessionKey, "StandardCharsets.UTF_8");
                            String t1 = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                            String sendSessionKey = sessionKeyString + "|" + t1;
                            String signedSessionKeyMsg = x.signMessage(sendSessionKey);
                            String sessionKeyMessage = x.encryptWithClientPub(signedSessionKeyMsg);
                            x.clientOut.println(sessionKeyMessage);

                            String input3 = x.decryptWithSharedKey(inputLine);
                            if (voters.contains(input3)) //Do not allow duplicate voters
                                break;
                            voters.add((input3));
                            //names.add((input)); Not sure what the client message format is
                            //sin.add((input)); Not sure what the client message format is


                            //create validation number for voter and send to them
                            String vc = generateVerfication();

                            //save new validation number to list
                            CLA.addToFile(input + " " + vc);

                            //Create TimeStamp
                            String t3 = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new java.util.Date());
                            String sendVerificationNumber = vc + "|" + t3;
                            //Send verification number to CTF and client
                            String encryptedOut = x.encryptWithSharedKey(sendVerificationNumber);
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
                    x.ctfOut.close();
                    x.ctfIn.close();
                    x.clientOut.close();
                    x.clientIn.close();
                    System.out.println("Connection lost, closing connection.");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
