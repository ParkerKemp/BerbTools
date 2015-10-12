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
	}
	
	public MessageSender getSender(){
		return entity.getSender(socket, crypt);
	}
	
	public boolean sendMessage(MessageSender sender) throws IOException{
		return sender.sendEncrypted(sessionKey);
	}
	
	public MessageReceiver receiveMessage(){
		MessageReceiver receiver = entity.getReceiver(socket, crypt);
		receiver.receiveMessage(sessionKey);
		return receiver;
	}
}
