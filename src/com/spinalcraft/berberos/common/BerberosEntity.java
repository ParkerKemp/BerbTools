package com.spinalcraft.berberos.common;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosEntity {
	protected String berberosAddress;
	protected int berberosPort;
	protected EasyCrypt crypt;
	
	public BerberosEntity(String berberosAddress, int berberosPort, EasyCrypt crypt){
		this.berberosAddress = berberosAddress;
		this.berberosPort = berberosPort;
		this.crypt = crypt;
	}
	
	public abstract MessageSender getSender(Socket socket, EasyCrypt crypt);
	
	public abstract MessageReceiver getReceiver(Socket socket, EasyCrypt crypt);
	
	protected Socket connectTo(String address, int port){
		return connectTo(address, port, 5000);
	}
	
	protected Socket connectTo(String address, int port, int timeout){
		return connectTo(address, port, timeout, 1);
	}
	
	protected Socket connectTo(String address, int port, int timeout, int attempts){
		Socket socket = new Socket();
		while(attempts-- > 0){
			try {
				socket.setSoTimeout(timeout);
				socket.connect(new InetSocketAddress(address, port), timeout);
				attempts = 0;
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				Thread.sleep(timeout);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		if(socket.isConnected())
			return socket;
		return null;
	}
}
