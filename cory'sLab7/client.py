# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
#Cory Beaunoyer
#ID 3115478

import socket
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def openKey(keyName):
    keyFile = open(keyName, "rb")
    key = keyFile.read()
    cipher = AES.new(key, AES.MODE_ECB)
    keyFile.close()
    return cipher

#============================================================================================================
def encrypt(cipher, message):

    encodedMessage = message.encode('ascii')
    paddingMessage = pad(encodedMessage, int(256/8))
    encryptedMessage = cipher.encrypt(paddingMessage)
    return encryptedMessage
   
#=============================================================================================================
def decrypt(cipher, encryptedMessage):
    paddedMessaged = cipher.decrypt(encryptedMessage)
    unPaddedMessage = unpad(paddedMessaged, int(256/8))
    decodedMessage = unPaddedMessage.decode('ascii')
    return decodedMessage
  
#=============================================================================================================  

def client():
    # Server Information
    #serverName = '127.0.0.1' #'localhost'
    serverPort = 12000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    serverName = input("Enter the server IP or name: ")
    cipher = openKey("key") #Get cipher
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        welcome = clientSocket.recv(2048)
        welcome = decrypt(cipher,welcome)
        print(welcome)
        name = input()
        name = encrypt(cipher, name)
        clientSocket.send(name)
        
        while True:
            for i in range(1,5):
                question1 = clientSocket.recv(2048)
                question1 = decrypt(cipher, question1)
                print(question1)
                answer = input("answer: ")
                answer = encrypt(cipher, answer)
                clientSocket.send(answer)
        
            results = clientSocket.recv(2048)
            results = decrypt(cipher, results)
            print(results)
            response = input()
            response = encrypt(cipher, response)
            clientSocket.send(response)
            response = decrypt(cipher, response)
            if (response == "y" or response == "Y"):
                print() 
                continue
            else:
                break
            
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
