/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package coe817project;

import java.awt.event.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;

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
    private static String validationNum;
    private static String candidate;
    
    public Client() {
        
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
            public void actionPerformed(ActionEvent arg0) {

                System.out.println(fname.getText());

                try (
                    // to CLA
                    Socket sockCla = new Socket("localhost",6969); 
                    PrintWriter out = new PrintWriter(sockCla.getOutputStream(), true); 
                    BufferedReader in = new BufferedReader(new InputStreamReader(sockCla.getInputStream()));) {
                    BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
                    
                    String fromServer;
                    
                    System.out.println("Sending to CLA: " + sin.getText()); // SIN = voter ID
                    out.write(Base64.getEncoder().encodeToString(sin.getText().getBytes()));
                    
                    fromServer = in.readLine();

                    byte[] decoded = Base64.getDecoder().decode(fromServer);
                    String[] split = new String(decoded).split("\\|");
                    validationNum = split[0];
                    System.out.println("validation number: " + fromServer);
                    
                } catch (IOException ex) {
                
                }
                
                //JLabel validationNum = new JLabel(fromServer);
                cl.show(container, "2");
            }
        });
        
        vote.addActionListener(new ActionListener () {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                
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

                System.out.println(candidate + sin.getText());

                try (
                    // to CTF
                    Socket sockCtf = new Socket("localhost",9090); 
                    PrintWriter out = new PrintWriter(sockCtf.getOutputStream(), true); 
                    BufferedReader in = new BufferedReader(new InputStreamReader(sockCtf.getInputStream()));) {
                    BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
                    String fromServer;
                    
                    if (!voters.isEmpty()) { 
                        out.write("Client");

                        System.out.println("Sending to CTF: " + validationNum + "|" + candidate + "|" + sin.getText());
                        // encrypt and encode this entire string before writing
                        out.write(validationNum + "|" + candidate + "|" + sin.getText());

                        // if voter is in list, remove them
                        if(voters.contains(sin.getText())) {
                            voters.remove(sin.getText());
                        }
                    } else {
                        out.write("Finished");
                        
                        fromServer = in.readLine();
                        byte[] decoded = Base64.getDecoder().decode(fromServer);
                        // decrypt decoded message here
                        
                        String[] splitResults = new String(decoded).split("\\|");
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
                    
                } catch (IOException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        
        frame.add(container);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(300, 300);
        frame.setVisible(true);
    }

    public static void main(String[] args) {
        Client client = new Client();
    }
}
