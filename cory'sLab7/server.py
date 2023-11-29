# This is an example from "Computer Networking: A Top Down Approach" textbook chapter 2
# You can try this with nc localhost 12000
# See the following link for more details about the socket liberary (https://docs.python.org/3/library/socket.html)

#Cory Beaunoyer
#ID 3115478
import socket
import os
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def makeQuestion():
    num1 = random.randrange(0,1001)
    num2 = random.randrange(0,1001)
    operation = random.randrange(1,4)
    
    if operation == 1:
        operation = "+"
        answer = num1 + num2
    
    if  operation == 2:
        operation = "-"
        answer = num1 - num2
    
    if operation == 3:
        operation = "*"
        answer = num1 * num2
    
    return num1,num2, operation, answer

#===========================================================================================================
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

def handleClients(connectionSocket, cipher):
    welcome = encrypt(cipher, "Welcome to examination System\n\nPlease enter your name: ")
    connectionSocket.send(welcome)  
    userName = connectionSocket.recv(2048)
    userName = decrypt(cipher, userName)
    while True:
        correct = 0
        for i in range(1,5):
            num1, num2, operation, answer = makeQuestion()
            question = f"Question {i}: {num1} {operation} {num2} = "
            question = encrypt(cipher, question)
            connectionSocket.send(question)
            response = connectionSocket.recv(2048)
            response = decrypt(cipher, response)
            if int(response) == answer:
                correct+=1
        
        results = f"You achieved a score of {correct}/4\nWould you like to try again? (y/n)"
        results = encrypt(cipher, results)
        connectionSocket.send(results)
        reply = connectionSocket.recv(2048)
        reply = decrypt(cipher, reply)
        reply = reply.strip()
        if (reply == "y" or reply == "Y" ):
            continue
        else:
            connectionSocket.close() 
            return 
        
#============================================================================================           
def server():
    #Server port
    serverPort = 12000
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
   
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
    cipher = openKey("key")

    while True:
        connectionSocket, addr = serverSocket.accept()
        print(f"Accepted connection from {addr}")


        # Fork a child process to handle the client
        pid = os.fork()
        
        if pid == 0:
            # This code runs in the child process
            handleClients(connectionSocket, cipher)
            sys.exit(0)  # Child process exits

        connectionSocket.close()
    
      
#-------
server()
