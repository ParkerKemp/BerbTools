package com.spinalcraft.berberos.common;

import java.net.Socket;

import com.spinalcraft.easycrypt.EasyCrypt;
import com.spinalcraft.easycrypt.messenger.MessageReceiver;
import com.spinalcraft.easycrypt.messenger.MessageSender;

public abstract class BerberosEntity {
	public abstract MessageSender getSender(Socket socket, EasyCrypt crypt);
	
	public abstract MessageReceiver getReceiver(Socket socket, EasyCrypt crypt);
}
