import java.security.*;
import java.io.*;
import java.text.*;
import java.util.*;
import javax.crypto.*;
import java.net.*;
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


    private static final File file = new File(System.getProperty("user.dir") + "\\coe817-project\\CLA.txt");
    private static Scanner s;

    private static final ArrayList<String> voters = new ArrayList<>();
    private static final ArrayList<String> names = new ArrayList<>();
    private static final ArrayList<Integer> sin = new ArrayList<>();

    private static String firstName, lastName, sinID;

    private static Integer sinNum;

    CLA(SecretKey key) throws Exception {
        enc_cip = Cipher.getInstance("DES/CBC/PKCS5Padding");
        dec_cip = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec iv2 = new IvParameterSpec(new byte[8]);
        enc_cip.init(Cipher.ENCRYPT_MODE, key, iv2);
        dec_cip.init(Cipher.DECRYPT_MODE, key, iv2);
    }

    public static String encrypt(String encryptTxt) throws Exception {
        byte[] utf8 = encryptTxt.getBytes("UTF8");

        byte[] enc = enc_cip.doFinal(utf8);

        return Base64.getEncoder().encodeToString(enc);
    }

    public static String decrypt(String decryptTxt) throws Exception {
        byte[] dec = Base64.getDecoder().decode(decryptTxt);

        byte[] utf8 = dec_cip.doFinal(dec);

        return new String(utf8, "UTF8");
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


    public static void main(String[] args) {
        int portNumber = 6969;
        int portNumberServer = 9090;
        try {
            String encodedKey = "TW9ua2U=";
            System.out.println("{"+encodedKey+"}");
            byte[] decodedKey = encodedKey.getBytes();
            SecretKey originalKey = new SecretKeySpec(decodedKey, "DES");
            System.out.println(originalKey);

            CLA x = new CLA(originalKey);

            while (true) {
                //connect to voter
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
                            String input = decrypt(inputLine);
                            System.out.println("Message received :" + input);

                            if (voters.contains(input)) //Do not allow duplicate voters
                                break;
                            voters.add((input)); 
                            //names.add((input)); Not sure what the client message format is
                            //sin.add((input)); Not sure what the client message format is


                            //create validation number for voter and send to them
                            String vc = generateVerfication();

                            //save new validation number to list
                            CLA.addToFile(input + " " + vc);

                            //Send verification number to CTF and client
                            String encryptedOut = encrypt(vc);
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
