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

# ------------------------------------------------------------------------------
# Load server keys and user credentials
# ------------------------------------------------------------------------------

# Load the server's private RSA key from a file
with open('server_private.pem', 'rb') as keyFile:
    serverPrivKey = RSA.import_key(keyFile.read())

# Load the usernames and passwords for client authentication from a JSON file
with open('user_pass.json', 'r') as user_passFile:
    user_passData = json.load(user_passFile)
    
# ------------------------------------------------------------------------------
# Create a dictionary to store client public keys
# ------------------------------------------------------------------------------

# Initializing a dictionary to hold public RSA keys of all clients
clientPubKeys = {}
for username in user_passData:
    # Load and store each client's public RSA key
    with open(f'{username}_public.pem', 'rb') as pubKeyFile:
        clientPubKeys[username] = RSA.import_key(pubKeyFile.read())

# ------------------------------------------------------------------------------
# Helper functions for server
# ------------------------------------------------------------------------------

# Function to authenticate clients
def authenticateClient(connectionSocket):
    """
    Purpose: Authenticate the client using the received username and password.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
    Return:
        - str: The username of the authenticated client or None if authentication fails.
    """
    try:
        # Receiving encrypted username and password from the client
        # Ensure to receive exactly 256 bytes for each
        encryptedUser = connectionSocket.recv(256)
        encryptedPass = connectionSocket.recv(256)

        # Decrypting the received credentials using the server's private key
        decryptor = PKCS1_OAEP.new(serverPrivKey)
        username = decryptor.decrypt(encryptedUser).decode('ascii')
        password = decryptor.decrypt(encryptedPass).decode('ascii')

        # Validating the decrypted credentials
        if username in user_passData and user_passData[username] == password:
            print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
            return username, True
        else:
            print(f"The received client information: {username} is invalid (Connection Terminated).")
            return None, False
    except Exception as e:
        print(f"Authentication error: {e}")
        return None, False
    
def sendEncryptedMsg(connectionSocket, message, symKey):
    """
    Purpose: Encrypt and send a message to the client.
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
    Purpose: Receive and decrypt an encrypted message from the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - symKey (bytes): The symmetric key for AES decryption.
    Returns:
        - str: The decrypted message.
    """
    encryptedMsg = connectionSocket.recv(1024)
    cipher = AES.new(symKey, AES.MODE_ECB)
    decryptedMsg = unpad(cipher.decrypt(encryptedMsg), AES.block_size)
    return decryptedMsg.decode('ascii')

def processAndStoreEmail(email, senderUsername):
    """
    Purpose: Process the received email JSON and store it in the recipient's directory.
    Parameters:
        - email (dict): The email information as a dictionary.
        - senderUsername (str): The username of the email sender.
    Return:
        - None
    """
    # Adding the current date and time to the email
    email['Time and Date'] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Processing each recipient in the email
    recipients = email['To'].split(';')

    for recipient in recipients:
        # Creating a directory for the recipient if it does not exist
        recipientDir = os.path.join('ClientFolders', recipient)
        if not os.path.exists(recipientDir):
            os.makedirs(recipientDir)

        # Saving the email as a JSON file in the recipient's directory
        emailFilename = f"{senderUsername}_{email['Title'].replace(' ', '_')}.json"
        with open(os.path.join(recipientDir, emailFilename), 'w') as emailFile:
            json.dump(email, emailFile)

        print(f"Email from {senderUsername} to {recipient} stored successfully.")

def displayInboxList(connectionSocket, username, symKey):
    """
    Purpose: Send the list of emails in the user's inbox to the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - username (str): The username of the client whose inbox is being accessed.
        - symKey (bytes): The symmetric key for AES encryption.
    Return:
        - None
    """
    # Locating the inbox directory of the client
    inboxDir = os.path.join('ClientFolders', username)

    # Listing all files (emails) in the inbox directory
    inboxList = os.listdir(inboxDir) if os.path.exists(inboxDir) else []
    inboxListStr = '\n'.join(inboxList)

    # Sending the list of emails to the client
    sendEncryptedMsg(connectionSocket, inboxListStr, symKey)

def displayEmailContents(connectionSocket, username, symKey):
    """
    Purpose: Send the contents of a specific email to the client.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - username (str): The username of the client requesting the email content.
        - symKey (bytes): The symmetric key for AES encryption.
    Return:
        - None
    """
    # Prompting the client to enter the index of the email they wish to view
    sendEncryptedMsg(connectionSocket, "Enter email index:", symKey)
    emailIndex = recvDecryptedMsg(connectionSocket, symKey)

    try:
        # Opening and reading the requested email file
        emailFilename = os.path.join('ClientFolders', username, emailIndex)
        with open(emailFilename, 'r') as emailFile:
            emailContent = json.load(emailFile)
            emailContentStr = json.dumps(emailContent, indent=4)

            # Sending the email content to the client
            sendEncryptedMsg(connectionSocket, emailContentStr, symKey)
            
    except Exception as e:
        # Handling errors in reading the email file
        sendEncryptedMsg(connectionSocket, f"Error reading email: {e}", symKey)

def handleEmailOperations(connectionSocket, username, symKey):
    """
    Purpose: Handle various email-related operations based on client's choice.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - username (str): The authenticated username of the client.
        - symKey (bytes): The symmetric key for AES encryption/decryption.
    Return:
        - None
    """
    # Presenting the email operation menu to the client
    menu = '''Select the operation:
    1) Create and send an email
    2) Display the inbox list
    3) Display the email contents
    4) Terminate the connection
    choice: '''
    sendEncryptedMsg(connectionSocket, menu, symKey)
    
    # Receiving the client's choice
    choice = recvDecryptedMsg(connectionSocket, symKey)
    
    # Handling the client's choice
    if choice == '1':
        # Handling email creation and sending
        sendEncryptedMsg(connectionSocket, "Send the email details", symKey)
        email_json = recvDecryptedMsg(connectionSocket, symKey)
        email = json.loads(email_json)
        processAndStoreEmail(email, username)
    elif choice == '2':
        # Handling inbox listing
        displayInboxList(connectionSocket, username, symKey)
    elif choice == '3':
        # Handling displaying email contents
        displayEmailContents(connectionSocket, username, symKey)
    elif choice == '4':
        # Handling connection termination
        print(f"Terminating connection with {username}")
    else:
        # Handling invalid choices
        sendEncryptedMsg(connectionSocket, "Invalid choice, please try again.", symKey)

def handleClient(connectionSocket):
    """
    Purpose: Manage the lifecycle of a client connection including authentication and email operations.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
    Return:
        - None
    """
    # Authenticating the client
    username, auth_success = authenticateClient(connectionSocket)

    if not auth_success:
        connectionSocket.send(b"FAILURE")
        connectionSocket.close()
        return

    connectionSocket.send(b"SUCCESS")

    # Generating a symmetric AES key for encrypted communication
    symKey = get_random_bytes(16)

    # Encrypting the symmetric key with the client's public RSA key and sending it
    clientPubKey = clientPubKeys[username]
    encryptor = PKCS1_OAEP.new(clientPubKey)
    encryptedSymKey = encryptor.encrypt(symKey)
    connectionSocket.send(encryptedSymKey)

    # Handling email operations
    handleEmailOperations(connectionSocket, username, symKey)

    # Closing the connection socket after operations are complete
    connectionSocket.close()

# Main function to start and run the server
def server():
    """
    Purpose: Initialize and run the email server, listening for client connections.
    Return:
        - None
    """
    # Creating a TCP socket and binding it to a port
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind(('localhost', 13000))
    serverSocket.listen(5)

    # Server is ready and waiting for connections
    print("Server is ready to accept connections")

    while True:
        # Accepting a new connection from a client
        connectionSocket, addr = serverSocket.accept()
        print(f"Accepted connection from {addr}")
        
        # Forking a new process for each client connection
        pid = os.fork()
        if pid == 0:  # In the child process
            serverSocket.close()
            handleClient(connectionSocket)
            sys.exit(0)
        else:  # In the parent process
            connectionSocket.close()

# Run the server program
if __name__ == "__main__":
    server()