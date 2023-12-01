'''
Student names: - Arfaa Mumtaz
               - Cory Beaunoyer
               - Kevin Esperida
               - Olasubomi Badiru
Instructor name: Mahdi Firoozjaei
Assignment: Secure Mail Transfer Project
Program name: Client.py
Program purpose: <TODO>
'''

#------------------------------------------------------------------------------
# Import statements
#------------------------------------------------------------------------------
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

#------------------------------------------------------------------------------
# Load private and public keys for all clients, and load public key for server
#------------------------------------------------------------------------------
def loadPrivateKey(username):
    """
    Purpose: Load the client's private RSA key from a file.
    Parameters:
        - username (str): The client's username.
    Return:
        - RSA key: The client's private RSA key.
    """
    try:
        with open(f'{username}_private.pem', 'rb') as privKeyFile:
            privKey = RSA.import_key(privKeyFile.read())
        return privKey
    
    except FileNotFoundError:
        print(f"Private key for {username} not found in directory")
        return None
    
def loadPublicKey(username):
    """
    Purpose: Load the client's or the server's public RSA key from a file.
    Parameters:
        - username (str): The client's username or "server".
    Return:
        - RSA key: The client's or server's public RSA key.
    """
    try:
        with open(f'{username}_public.pem', 'rb') as pubKeyFile:
            pubKey = RSA.import_key(pubKeyFile.read())
        return pubKey
    
    except FileNotFoundError:
        print(f"Public key for {username} not found in directory")
        return None
    
#------------------------------------------------------------------------------
# Helper functions for client
#------------------------------------------------------------------------------
def encryptMessage(message, key):
    """
    Purpose: Encrypt a message using AES encryption in ECB mode.
    Parameters:
        - message (str): The message to be encrypted.
        - key (bytes): The symmetric key for AES encryption.
    Return:
        - bytes: The encrypted message.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    encryptedMsg = cipher.encrypt(pad(message.encode('ascii'), AES.block_size))
    return encryptedMsg

def decryptMessage(encryptedMsg, key):
    """
    Purpose: Decrypt a message using AES decryption in ECB mode.
    Parameters:
        - encryptedMsg (bytes): The encrypted message.
        - key (bytes): The symmetric key for AES decryption.
    Return:
        - str: The decrypted message.
    """
    if not encryptedMsg:
        raise ValueError("The encrypted message is empty")
    
    cipher = AES.new(key, AES.MODE_ECB)
    decryptedMsg = unpad(cipher.decrypt(encryptedMsg), AES.block_size)
    return decryptedMsg.decode('ascii')

def getEmailDetails():
    # Function to get email details from the user
    destinations = input("Enter destinations (separated by ;): ")
    title = input("Enter title: ")

    if len(title) > 100:
        print("Title exceeds 100 characters. Please retry.")
        return None, None, None
    
    choice = input("Would you like to load contents from a file? (Y/N): ")

    if choice.lower() == 'y':
        filename = input("Enter filename: ")
        try:
            with open(filename, 'r') as file:
                content = file.read()

        except FileNotFoundError:
            print("File not found. Please retry.")
            return None, None, None
        
    else:
        content = input("Enter message contents: ")

    if len(content) > 1000000:
        print("Content exceeds 1,000,000 characters. Please retry.")
        return None, None, None
    
    return destinations, title, content

def sendEmail(clientSocket, symKey, username):
    # Function to send email
    destinations, title, content = getEmailDetails()

    if destinations and title and content:
        email = {
            "From": username,
            "To": destinations,
            "Title": title,
            "Content Length": len(content),
            "Content": content
        }

        email_json = json.dumps(email)
        clientSocket.send(encryptMessage(email_json, symKey))
        print("The message is sent to the server.")
    else:
        print("Email sending aborted.")

def displayInboxList(clientSocket, symKey):
    # Function for displaying inbox list
    # Request inbox list from server
    clientSocket.send(encryptMessage("2", symKey))  # '2' represents the choice for displaying inbox
    inboxList = decryptMessage(clientSocket.recv(1024), symKey)
    print("Inbox List:\n", inboxList)

def displayEmailContents(clientSocket, symKey):
    # Function to display the contents of a specific email
    # Request specific email content from server
    emailIndex = input("Enter the email index you wish to view: ")
    clientSocket.send(encryptMessage(emailIndex, symKey))
    emailContent = decryptMessage(clientSocket.recv(1024), symKey)
    print("Email Content:\n", emailContent)

#------------------------------------------------------------------------------
# Main client function
#------------------------------------------------------------------------------
def client():
    """
    Main client function to handle the connection and communication with the server.
    It handles user authentication and subsequent mail operations.
    """
    # Server IP address and port number
    serverIP = input("Enter the server IP or name: ")
    serverPort = 13000

    # Create a socket to connect to the server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((serverIP, serverPort))

    # Authenticate the client with the server and receive the symmetric key
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Encrypt the username and password with the server's public key
    serverPubKey = loadPublicKey("server")
    cipher = PKCS1_OAEP.new(serverPubKey)

    # Ensure username and password are within RSA encryption limit
    if len(username.encode('ascii')) > 245 or len(password.encode('ascii')) > 245:
        print("Username or password too long for RSA encryption.")
        return
    
    encryptedUser = cipher.encrypt(username.encode('ascii'))
    encryptedPass = cipher.encrypt(password.encode('ascii'))

    # Send the encrypted username and password to the server
    clientSocket.send(encryptedUser)
    clientSocket.send(encryptedPass)

    # Receive response from server
    serverResponse = clientSocket.recv(1024)

    # Receive and decrypt the symmetric key from the server
    encryptedSymKey = clientSocket.recv(256)
    privateKey = loadPrivateKey(username)

    if privateKey is None:
        print("Error: Private key not found.")
        return
    
    symKeyCipher = PKCS1_OAEP.new(privateKey)
    symKey = symKeyCipher.decrypt(encryptedSymKey)

    if serverResponse == b"FAILURE":
        print("Invalid username or password.\nTerminating.")
        clientSocket.close()
        return
    
    symKey = symKeyCipher.decrypt(encryptedSymKey)

    # Check for invalid username or password response
    if symKey == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        clientSocket.close()
        return
    
    if symKey is not None:
        # Start the user interaction loop
        while True:
            # Receive menu from server
            menu = decryptMessage(clientSocket.recv(1024), symKey)
            print(menu)

            # Get user choice
            choice = input("Enter your choice (1-4): ")
            clientSocket.send(encryptMessage(choice, symKey))

            # Handle user choice
            match choice:
                case '1':
                    sendEmail(clientSocket, symKey, username)
                case '2':
                    displayInboxList(clientSocket, symKey)
                case '3':
                    displayEmailContents(clientSocket, symKey)
                case '4':
                    print("The connection is terminated with the server.")
                    break
                case _:
                    print("Invalid choice. Please try again.")

        # Close the client socket when done
        clientSocket.close()

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Run program
#------------------------------------------------------------------------------
if __name__ == "__main__":
    client()