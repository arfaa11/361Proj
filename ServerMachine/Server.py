'''
Student names: - Arfaa Mumtaz
               - Cory Beaunoyer
               - Kevin Esperida
               - Olasubomi Badiru
Instructor name: Mahdi Firoozjaei
Assignment: Secure Mail Transfer Project
Program name: Server.py
Program purpose: <TODO>
'''

import json
import socket
import os
import sys
import datetime as dt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#------------------------------------------------------------------------------
# Load server keys and user credentials
#------------------------------------------------------------------------------

# Load the server's private RSA key from a file.
# Will be used to decrypt messages that are encrypted with the server's 
# public key.
with open('server_private.pem', 'rb') as keyFile:
    serverPrivKey = RSA.import_key(keyFile.read())

# Load the usernames and passwords from user_pass.json.
# Will be used for authenticating clients.
with open('user_pass.json', 'r') as user_passFile:
    user_passData = json.load(user_passFile)

#------------------------------------------------------------------------------
# Create a dictionary to store client public keys
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Email Index Database Structure# {index<int>: [destination<string>, timeanddate<string>, title<string>, content_length<int>,emailcontents<string>/filename<string>]}   

# Format for each user's json fileName:- <username>.json

# Create a dictionary to hold each client's public RSA key.
clientPubKeys = {}
for username in user_passData:
    with open(f'{username}_public.pem', 'rb') as pubKeyFile:
        clientPubKeys[username] = RSA.import_key(pubKeyFile.read())


#------------------------------------------------------------------------------
# Helper functions for server
#------------------------------------------------------------------------------

def authenticateClient(connectionSocket):
    """
    Purpose: Authenticate the client using the received username and password.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
    Return:
        - str: The username of the authenticated client or None if authentication fails.
    """
    print("Begin authentication")

    try:
        # Receive the encrypted username and password from the client
        encryptedUser = connectionSocket.recv(256)
        encryptedPass = connectionSocket.recv(256)

        # Decrypt using the server's private key
        decryptor = PKCS1_OAEP.new(serverPrivKey)
        username = decryptor.decrypt(encryptedUser).decode()
        print("Username gotten")
        password = decryptor.decrypt(encryptedPass).decode()

        # Check if the username and password are valid
        if username in user_passData and user_passData[username] == password:
            print(f"Authentication successful for {username}")
            return username
        else:
            print(f"Authentication failed for {username}")
            return None

    

    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def sendEncryptedMsg(connectionSocket, message, symKey):
    """
    Purpose: Send an encrypted message to the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - message (str): The message to be sent.
        - symKey (bytes): The symmetric key for AES encryption.
    Return:
        - None
    """
    cipher = AES.new(symKey, AES.MODE_ECB)
    encryptedMsg = cipher.encrypt(pad(message.encode('ascii'), AES.block_size))
    connectionSocket.send(encryptedMsg)
    return

def recvDecryptedMsg(connectionSocket, symKey):
    """
    Purpose: Receive an encrypted message from the client and decrypt it. 
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - symKey (bytes): The symmetric key for AES decryption.
    Returns:
        str: The decrypted message.
    """
    encryptedMsg = connectionSocket.recv(1024)
    cipher = AES.new(symKey, AES.MODE_ECB)
    decryptedMsg = unpad(cipher.decrypt(encryptedMsg), AES.block_size)
    return decryptedMsg.decode('ascii')

def handleEmailOperations(connectionSocket, username, symKey):
    """
    Purpose: Function to handle email related operations with the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - username (str): The authenticated username of the client.
    Modification by Subomi: added symKey to function parameters
    Return:
        - ---
    """
    ''' <TODO> '''
    # Haven't worked on this yet, we will do this once everything else is
    # in perfect working order

    
    
    choice = getChoice(connectionSocket,symKey)
    while (choice):
        match choice:
            case 1:
                print("the sending email subprotocol")
                sendEmailProtocol(connectionSocket,symKey, username)
            case 2:
                print("the viewing inbox subprotocol")
                viewInboxProtocol(connectionSocket,symKey, username)
            case 3:
                print("the viewing email subprotocol")
                viewEmailProtocol(connectionSocket,symKey, username)
            case 4:
                print("connection termination subprotocol")
                connectionSocket.close()
                return
            case _:
                break
        choice = getChoice(connectionSocket,symKey)

    return

def sendEmailProtocol(connectionSocket,symKey, username):
    '''
    Description
    Function to handle email sending protocol
    inputs:
        connectionSocket (socket): The socket connected to the client.
        symKey (bytes): The symmetric key for AES decryption.
        username (str): The authenticated username of the client.
    Ouput:
        nothing, throws exceptions if error is encountered
    '''
    
    try:
        
        message = "Send the email"  
        # potential conflict here (conflicting spec instructions), check for server logic error in client.py
        sendEncryptedMsg(connectionSocket, message, symKey)
        
        # Get destinations
        message = "\nEnter destinations (separated by ;): "  
        sendEncryptedMsg(connectionSocket, message, symKey)
        
        dest = recvDecryptedMsg(connectionSocket, symKey)
        destS = dest.split(";")  #split into array of destination  

        # Get Email Title
        message = "\nEnter Title: "  
        sendEncryptedMsg(connectionSocket, message, symKey)
        
        title = recvDecryptedMsg(connectionSocket, symKey)
        
        # Get message
        message = "\nWould you like to load contents from a file?  (Y/N): "  
        sendEncryptedMsg(connectionSocket, message, symKey)
        
        choice = recvDecryptedMsg(connectionSocket, symKey)
        messageSize = 0
        '''TODO: Dump email contents to json file'''
        match choice.upper():
            case 'Y':
                ''' do some file transfer operations'''
                message = "\nEnter filename: "  
                sendEncryptedMsg(connectionSocket, message, symKey)

                fName = recvDecryptedMsg(connectionSocket, symKey)
                fName, fSize = fName.split(",")
                fSize = int(fSize)      # don't forget to get client to send file name and file size
                
                messageSize = fSize
                '''receive file'''
                with open(f'{fName}', 'rb') as fOut:
                    fOut = open(f"ServerReceive/{fName}", "wb")
                    data = recvDecryptedMsg(connectionSocket, symKey)
                    datalen = len(data)
                    
                    
                    while datalen < fSize:
                        if not data: # end loop if there's no more data
                            break
                        else:
                            fOut.write(data)
                            data = connectionSocket.recv(2048)
                            datalen += len(data)
                    '''Send message: The message is sent to the server? '''
            case 'N':
                message = "\nEnter message contents: "  
                sendEncryptedMsg(connectionSocket, message, symKey)
                
                email = recvDecryptedMsg(connectionSocket, symKey)
                messageSize = len(email)
            case _:
                pass
        

        print(f"An email from {username} is sent to {dest}, has content length of {messageSize}.")
    except Exception as e:
        print("Error occured while receiving email", e)
        return
    return

def viewInboxProtocol(connectionSocket,symKey, username):
    '''
    Desciption:
    Function to handle email sending protocol
    inputs:
        connectionSocket (socket): The socket connected to the client.
        symKey (bytes): The symmetric key for AES decryption.
        username (str): The authenticated username of the client.
    Ouput:
        nothing, throws exceptions if error is encountered
    '''
    #Get data from json file

    #Turn data to string text

    sendMessage = f"Index\t\t\tFrom\t\tDateTime\t\t\t\t\tTitle"
                        
                        
    # Read database from json file
    fOpen = open({username}.json,"r")
    #Format for each user's json file:- <username>.json
    
    
    try:
        dBase = json.load(fOpen)
        fOpen.close()                            
    except Exception as e:
        print(e)
                                
        
    for item,x in dBase, len(dBase):
        sendMessage += f"\n{x}\t\t\t{dBase[item]['From']}\t\t{dBase[item]['DateTime']}\t\t\t\t\t{dBase[item]['Title']}"
        
    sendMessage += "\n"
    sendEncryptedMsg(connectionSocket, sendMessage, symKey)  

    return

def viewEmailProtocol(connectionSocket,symKey, username):
    '''
    Description:

    inputs:
        connectionSocket (socket): The socket connected to the client.
        symKey (bytes): The symmetric key for AES decryption.
        username (str): The authenticated username of the client.
    Ouput:
        nothing, throws exceptions if error is encountered
    '''
    try:
        message = "\nEnter the email index you wish to view: "  
        sendEncryptedMsg(connectionSocket, message, symKey)
        
        index = recvDecryptedMsg(connectionSocket, symKey)
        
        try:
            fOpen = open({username}.json,"r")
            dBase = json.load(fOpen)
            fOpen.close()  
            # Email Index Database Structure
            # {index<int>: [destination<string>, timeanddate<string>, title<string>, content_length<int>,emailcontents<string>/filename<string>]}   
            retEmail = (f"From: {username}\nTo: {dBase[index][0]}\nTime and Date Received: {dBase[index][1]}"
                         f"\nTitle: {dBase[index][2]}\nContent Length: {dBase[index][3]}\nContents:\n{dBase[index][4]}")      
            
            #!!!currently arbitrary positions in dBase    

            sendEncryptedMsg(connectionSocket, retEmail, symKey) # send email info back to client       
        except Exception as e:
            sendEncryptedMsg(connectionSocket, "Email Index not Found", symKey) # Notify client. email index not found
            print(e)
            return
    except Exception as e:
        print(e)

    return


def getChoice(connectionSocket,symKey):
    '''
    Get choice from user
    Input:
            connectionSocket (socket): The socket connected to the client.
            symKey (bytes): The symmetric key for AES decryption.
    Output:
    '''
    menumessage = ("\nSelect the operation:\n\t1) Create and send and email"
                "\n\t2) Display the inbox list\n\t3) Display the email contents"
                "\n\t4) Terminate the connection\nchoice:")
    
    sendEncryptedMsg(connectionSocket, menumessage, symKey)
    choice = recvDecryptedMsg(connectionSocket, symKey)
    
    return int(choice)
    
    

def handleClient(connectionSocket):
    """
    Purpose: Handle the entire lifecycle of a client connection including authentication,
             symmetric key exchange, and email operations.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
    Return: 
        - None
    """
    # Authenticate the client
    username = authenticateClient(connectionSocket)
    if username is None:
        # Send a message indicating invalid credentials and close the connection
        connectionSocket.send(b"Invalid username or password")
        connectionSocket.close()
        return

    # Generate a symmetric AES key for encrypted communication with the client
    symKey = get_random_bytes(16)
    
    # Encrypt the symmetric key with the client's public RSA key and send it
    clientPubKey = clientPubKeys[username]
    encryptor = PKCS1_OAEP.new(clientPubKey)
    encryptedSymKey = encryptor.encrypt(symKey)
    connectionSocket.send(encryptedSymKey)
    check = recvDecryptedMsg(connectionSocket, symKey)
   
    if check == "OK":
        #handleEmailOperations(connectionSocket, username, symKey)
        pass
    ''' <TODO> '''

    # We will add code here when we are done with the email subprotocol
    
    
    
    #handleEmailOperations(connectionSocket, username, symKey)

    
    
        
    
     
    # Also, as I said in the client program, let me know if there are any 
    # changes you guys want made, or if there's somethign you guys don't
    # understand, and I will do my best to explain it, and we can implement
    # any changes, and all things we have to add from here on out together

    # Close the connection socket
    connectionSocket.close()
    return

#------------------------------------------------------------------------------
# Main server function
#------------------------------------------------------------------------------
def server():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind(('localhost', 13001))
    serverSocket.listen(5)

    print("Server is ready to accept connections")

    while True:
        connectionSocket, addr = serverSocket.accept()  # Accepting a new connection
        print(f"Accepted connection from {addr}")
        
        # Fork a new process
        pid = os.fork()
        if pid == 0:  # Child process
            # Close the listening socket in the child process
            serverSocket.close()  
            # Handle the client using the connection socket
            handleClient(connectionSocket)  
            sys.exit(0)
        else:
            # Close the connection socket in the parent process
            connectionSocket.close()  
#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# Run program
#------------------------------------------------------------------------------
if __name__ == "__main__":
    server()
