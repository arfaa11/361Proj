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
    try:
        # Receive the encrypted username and password from the client
        encryptedUser = connectionSocket.recv(1024)
        encryptedPass = connectionSocket.recv(1024)

        # Decrypt using the server's private key
        decryptor = PKCS1_OAEP.new(serverPrivKey)
        username = decryptor.decrypt(encryptedUser).decode()
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

def handleEmailOperations(connectionSocket, username):
    """
    Purpose: Function to handle email related operations with the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - username (str): The authenticated username of the client.
    Return:
        - ---
    """
    ''' <TODO> '''
    # Haven't worked on this yet, we will do this once everything else is
    # in perfect working order
    pass

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

    ''' <TODO> '''
    # We will add code here when we are done with the email subprotocol
    
    # Also, as I said in the client program, let me know if there are any 
    # changes you guys want made, or if there's somethign you guys don't
    # understand, and I will do my best to explain it, and we can implement
    # any changes, and all things we have to add from here on out together

    # Close the connection socket
    connectionSocket.close()

#------------------------------------------------------------------------------
# Main server function
#------------------------------------------------------------------------------
def server():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind(('localhost', 13000))
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