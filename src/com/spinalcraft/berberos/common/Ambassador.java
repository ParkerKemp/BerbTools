package com.spinalcraft.berberos.common;

import java.io.IOException;
import java.net.Socket;

import javax.crypto.SecretKey;

import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public class Ambassador {
	protected Socket socket;
	protected SecretKey sessionKey;
	protected EasyCrypt crypt;
	protected BerberosEntity entity;
	
	public Ambassador(Socket socket, SecretKey sessionKey, EasyCrypt crypt, BerberosEntity entity){
		this.socket = socket;
		this.sessionKey = sessionKey;
		this.crypt = crypt;
		this.entity = entity;
	}
	
	public MessageSender getSender(){
		return entity.getSender(socket, crypt);
	}
	
	public boolean sendMessage(MessageSender sender){
		try {
			return sender.sendEncrypted(sessionKey);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	public MessageReceiver receiveMessage(){
		MessageReceiver receiver = entity.getReceiver(socket, crypt);
		if(receiver.receiveMessage(sessionKey))
			return receiver;
		return null;
	}
}
