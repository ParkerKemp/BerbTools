package com.spinalcraft.berberos.service;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.easycrypt.EasyCrypt;

public class ServerTask implements Runnable{
	
	private BerberosService service;
	private ServerSocket serverSocket;
	private SecretKey secretKey;
	private EasyCrypt crypt;
	
	public ServerTask(BerberosService service, ServerSocket serverSocket, SecretKey secretKey, EasyCrypt crypt){
		this.service = service;
		this.serverSocket = serverSocket;
		this.secretKey = secretKey;
		this.crypt = crypt;
	}

	@Override
	public void run() {
		Socket socket;
		while(true){
			try {
				socket = serverSocket.accept();
				new Thread(new AmbassadorTask(service, socket, secretKey, crypt)).start();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

}
