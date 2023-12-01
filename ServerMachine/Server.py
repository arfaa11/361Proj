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
# ------------------------------------------------------------------------------
# Import statements
# ------------------------------------------------------------------------------
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
# Access the clientInboxes.json dictionary
# ------------------------------------------------------------------------------
def readClientInboxes():
    """
    Purpose: Read the client inboxes from the clientInboxes.json file.
    Parameters:
        - None
    Return:
        - dict: The client inboxes dictionary.
    """
    # Check if the clientInboxes.json file exists
    try:
        # Read the client inboxes from the file
        with open('clientInboxes.json', 'r') as file:
            # Return the client inboxes dictionary
            return json.load(file)
    # If the file does not exist, return an empty dictionary
    except FileNotFoundError:
        # Return an empty dictionary
        return {'client1': [], 'client2': [], 'client3': [], 'client4': [], 'client5': []}
    
def writeClientInboxes(clientInboxes):
    """
    Purpose: Write the client inboxes to the clientInboxes.json file.
    Parameters:
        - clientInboxes (dict): The client inboxes dictionary.
    Return:
        - None
    """
    # Write the client inboxes to the file
    with open('clientInboxes.json', 'w') as file:
        json.dump(clientInboxes, file)

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
            # Handling valid credentials
            print(f"Connection Accepted and Symmetric Key Generated for client: {username}")
            # return username, True tuple
            return username, True
        
        else:
            # Handling invalid credentials
            print(f"The received client information: {username} is invalid (Connection Terminated).")
            # return None, False tuple
            return None, False
    
    except Exception as e:
        # Handling errors in authentication
        print(f"Authentication error: {e}")
        # return None, False tuple
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
    # Use AES in ECB mode to encrypt the message
    cipher = AES.new(symKey, AES.MODE_ECB)
    # Pad and encrypt the message, and encode it to bytes
    encryptedMsg = cipher.encrypt(pad(message.encode('ascii'), AES.block_size))
    # Send the encrypted message to the client
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
    # Receive the encrypted message from the client
    encryptedMsg = connectionSocket.recv(1024)
    # Use AES in ECB mode to decrypt the message
    cipher = AES.new(symKey, AES.MODE_ECB)
    # Decrypt the message and unpad it
    decryptedMsg = unpad(cipher.decrypt(encryptedMsg), AES.block_size)
    # Decode the decrypted message to ASCII and return
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
    emailInfo['Time and Date'] = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    recipients = emailInfo['To'].split(';')

    clientInboxes = readClientInboxes()

    # Define the file name format
    title = email['Title'].replace(' ', '_')
    # Format: <senderUsername>_<emailTitle>.txt
    filename = f'{senderUsername}_{title}.txt'

    # Store the email in the recipient's directory
    for recipient in recipients:
        recipientDir = os.path.join('ClientFolders', recipient)
        
        # Create the recipient's directory if it does not exist
        if not os.path.exists(recipientDir):
            os.makedirs(recipientDir)

        # Write the email to a file
        try:
            with open(os.path.join(recipientDir, filename), 'w') as emailFile:
                emailFile.write(email['Content'])

            # Store the email information in thhe format below
            emailData = {
                'From': senderUsername,
                'DateTime': email['Time and Date'],
                'Title': title,
                'Content Length': len(email['Content'])
            }
            
            # Add the email to the recipient's inbox
            clientInboxes[recipient].append(emailData)
        
        # Handle errors in storing the email
        except:
            print(f"Failed to store email for {recipient}")
    
    # Write the updated inboxes to the file
    writeClientInboxes(clientInboxes)  


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
    # Read the client inboxes from the file
    clientInboxes = readClientInboxes()
    # Check if the client has an inbox
    if username in clientInboxes:
        inbox = clientInboxes[username]
    # If the client does not have an inbox, create an empty one
    else:
        inbox = []

    # Format the inbox list
    inboxListFormatted = "Index From DateTime Title\n"
    # Add each email to the formatted list
    index = 1
    for email in inbox:
        # Split sender and title
        sender, title = email['From'], email['Title']
        inboxListFormatted += f"{index} {sender} {email['DateTime']} {title}\n"
        # Increment the index
        index += 1

    # Send the formatted inbox list to the client
    sendEncryptedMsg(connectionSocket, inboxListFormatted, symKey)

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
    # Get the index of the email to be displayed
    sendEncryptedMsg(connectionSocket, "Enter email index:", symKey)
    emailIndex = int(recvDecryptedMsg(connectionSocket, symKey))

    # Read the client inboxes from the file
    clientInboxes = readClientInboxes()
    
    # Check if the client has an inbox
    try:
        if username in clientInboxes and 0 < emailIndex <= len(clientInboxes[username]):
            # Get the email information
            emailInfo = clientInboxes[username][emailIndex - 1]
            sender, title = emailInfo['From'], emailInfo['Title']
            dateTime = emailInfo['DateTime']
            contentLength = emailInfo['Content Length']
            # Adjust the title to match the file name format
            filename = f'{sender}_{title}.txt'
            # Get the path to the email file
            emailPath = os.path.join('ClientFolders', username, filename)

            # Read the email contents from the file
            with open(emailPath, 'r') as emailFile:
                content = emailFile.read()
                # Format the email content
                emailContentStr = f"From: {sender}\nTo: {emailInfo['To']}\nTime and Date Received: {dateTime}\nTitle: {title}\nContent Length: {contentLength}\nContents:\n{content}"

            # Send the formatted email content to the client
            sendEncryptedMsg(connectionSocket, emailContentStr, symKey)
        
        # Handle invalid email index
        else:
            sendEncryptedMsg(connectionSocket, "Invalid email index.", symKey)
    
    # Handle errors in reading the email
    except Exception as e:
        sendEncryptedMsg(connectionSocket, f"Error reading email: {e}", symKey)

def getChoice(connectionSocket, symKey):
    """
    Purpose: Get the client's choice of email operation.
    Parameters:
        - connectionSocket (socket): The socket connected to the client.
        - symKey (bytes): The symmetric key for AES encryption.
    Return:
        - str: The client's choice of email operation.
        """
    # Creating the email operation menu
    menumessage = ("\nSelect the operation:\n\t1) Create and send and email"
                "\n\t2) Display the inbox list\n\t3) Display the email contents"
                "\n\t4) Terminate the connection\n\tchoice: ")
    
    # Sending the encrypted menu to the client
    sendEncryptedMsg(connectionSocket, menumessage, symKey)
    
    # Receiving the client's choice
    choice = recvDecryptedMsg(connectionSocket, symKey)
    
    # Return the client's choice
    return choice

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
    # Presenting the email operation menu to the client and getting the choice
    #choice = getChoice(connectionSocket, symKey)
    while True:
    # Handling the client's choice
        choice = getChoice(connectionSocket, symKey)
        match choice:
            case '1':
            # Handling email creation and sending  
                # Receive content length first
                contentLength = int(recvDecryptedMsg(connectionSocket, symKey))
                # Receive the rest of the email information
                emailInfo = json.loads(recvDecryptedMsg(connectionSocket, symKey))
                processAndStoreEmail(emailInfo, username)
                # Print the email send confirmation message to server
                print(f"An email from {senderUsername} is sent to {';'.join(recipients)} has a content length of {contentLength}")
            case '2':
            # Handling inbox listing
                displayInboxList(connectionSocket, username, symKey)
            case '3':
            # Handling displaying email contents
                displayEmailContents(connectionSocket, username, symKey)
            case '4':
            # Handling connection termination
                print(f"Terminating connection with {username}")
                break
            case _:
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

    # Check if authentication was successful
    if not auth_success:
        # Sending a failure message to the client and closing the connection
        connectionSocket.send(b"FAILURE")
        connectionSocket.close()
        return

    # Sending a success message to the client
    connectionSocket.send(b"SUCCESS")

    # Generating a symmetric AES key for encrypted communication
    symKey = get_random_bytes(32)

    # Encrypting the symmetric key with the client's public RSA key and sending it
    clientPubKey = clientPubKeys[username]
    encryptor = PKCS1_OAEP.new(clientPubKey)
    encryptedSymKey = encryptor.encrypt(symKey)
    connectionSocket.send(encryptedSymKey)

    # Check if 'OK' received from client
    okResponse = recvDecryptedMsg(connectionSocket, symKey)
    if okResponse != "OK":
        print("Error: Did not receive OK from client.")
        return

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
            serverSocket.close() # Close the server socket in the child process
            handleClient(connectionSocket) # Handle the client connection
            sys.exit(0) # Exit the child process
        else:  # In the parent process
            connectionSocket.close() # Close the connection socket in the parent process

# Run the server program
if __name__ == "__main__":
    server()