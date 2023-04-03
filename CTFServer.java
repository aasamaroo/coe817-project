
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author w2quan
 */
public class CTFServer {
    public static void main(String[] args) throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(9090, 0, InetAddress.getLoopbackAddress())) { 
            while (true) {
	            new CTF(serverSocket.accept()).start();
	        }
	    } catch (IOException e) {
            System.err.println("Could not listen on port 9090");
            System.exit(-1);
        }
    }    
}
