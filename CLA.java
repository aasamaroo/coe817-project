package coe817project;

import java.security.*;
import java.io.*;
import java.text.*;
import java.util.*;
import javax.crypto.*;
import java.net.*;
import javax.crypto.spec.*;


public class CLA {

    Cipher enc_cip;
    Cipher dec_cip;
    private Socket socket = null;

    private static final File file = new File(System.getProperty("user.dir") + "\\coe817-project\\CLA.txt");
    private PrintWriter out;
    private BufferedReader in;
    private static Scanner s;

    private static final ArrayList<String> voters = new ArrayList<>();
    private static final ArrayList<String> names = new ArrayList<>();
    private static final ArrayList<Integer> sin = new ArrayList<>();

    private static String firstName, lastName, sinID;

    private static Integer sinNum;

    CLA(SecretKey key) throws Exception {
        enc_cip = Cipher.getInstance("DES");
        dec_cip = Cipher.getInstance("DES");
        enc_cip.init(Cipher.ENCRYPT_MODE, key);
        dec_cip.init(Cipher.DECRYPT_MODE, key);
    }

    public String encrypt(String encryptTxt) throws Exception {
        byte[] utf8 = encryptTxt.getBytes("UTF8");

        byte[] enc = enc_cip.doFinal(utf8);

        return Base64.getEncoder().encodeToString(enc);
    }

    public String decrypt(String decryptTxt) throws Exception {
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
        try {
            String encodedKey = "TW9ua2U2OQ==";
            System.out.println("{"+encodedKey+"}");
            byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
            System.out.println(originalKey);

            CLA x = new CLA(originalKey);

            while (true) {
                //connect to voter
                try {
                    x.socket = new Socket("localhost", portNumber);
                    x.out = new PrintWriter(clientSocket.getOutputStream(), true);
                    x.in = new BufferedReader(new InputStreamReader(x.socket.getInputStream()));

                    //wait for voter to request validation number
                    String inputLine;
                    System.out.println("Waiting for messages");
                    while (true) {
                        inputLine = x.in.readLine();
                        if (inputLine != null) {
                            System.out.println("Message recieved :" + inputLine);

                            //create validation number for voter and send to them
                            String vc = generateVerfication();

                            //save new validation number to list
                            CLA.addToFile(inputLine + " " + vc);

                            //Send verification number to CTF
                            x.out.println(vc);
                            System.out.println("vc sent:" + vc);
                            break;
                        } else {
                            System.out.println("null");
                        }
                    }

                    System.out.println("Done.\n");
                    x.out.close();
                    x.in.close();
                    System.out.println("Done.\n");

                } catch (Exception e) {
                    x.out.close();
                    x.in.close();
                    System.out.println("Connection lost, closing connection.");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}