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
        # Open and read the private key file specific to the user
        with open(f'{username}_private.pem', 'rb') as privKeyFile:
            privKey = RSA.import_key(privKeyFile.read())
        
        # Return the RSA private key
        return privKey
    
    except FileNotFoundError:
        # If the private key file is not found, print an error message
        print(f"Private key for {username} not found in directory")
        
        # Return None to indicate failure in key loading
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
        # Open and read the public key file specific to the user
        with open(f'{username}_public.pem', 'rb') as pubKeyFile:
            pubKey = RSA.import_key(pubKeyFile.read())
        
        # Return the RSA public key
        return pubKey
    
    except FileNotFoundError:
        # If the public key file is not found, print an error message
        print(f"Public key for {username} not found in directory")
        
        # Return None to indicate failure in key loading
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
    # Initialize AES cipher in ECB mode with symKey
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Encrypt the message after padding, and return the encrypted bytes
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
    # Check if the encrypted message is empty
    if not encryptedMsg:
        # Raise a ValueError if the encrypted message is empty
        raise ValueError("The encrypted message is empty")
    
    # Initialize AES cipher in ECB mode with symKey
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Unpad and decrypt the message and return the decrypted bytes
    decryptedMsg = unpad(cipher.decrypt(encryptedMsg), AES.block_size)
    return decryptedMsg.decode('ascii')

def getEmailDetails():
    """
    Purpose: Get details of an email from the user, including recipients, title, and content.
    Parameters: None
    Return: Tuple of (destinations, title, content) or (None, None, None) if input is invalid.
    """
    # Prompt user to enter the email recipients, separated by semicolons
    destinations = input("Enter destinations (separated by ;): ")
    # Prompt user to enter the email title
    title = input("Enter title: ")

    # Check if title length exceeds 100 characters
    if len(title) > 100:
        print("Title exceeds 100 characters. Please retry.")
        return None, None, None  # Return None tuple if title is too long
    
    # Ask user if they want to load email content from a file
    choice = input("Would you like to load contents from a file? (Y/N): ")

    # If user chooses to load from a file
    if choice.lower() == 'y':
        filename = input("Enter filename: ")  # Ask for the filename
        
        try:
            # Try opening and reading the file
            with open(filename, 'r') as file:
                content = file.read()  # Read the file content
        
        except FileNotFoundError:
            # Handle the case where the file does not exist
            print("File not found. Please retry.")
            return None, None, None  # Return None tuple if file not found
    else:
        # If user chooses to manually enter content
        content = input("Enter message contents: ")  # Prompt for email content

    # Check if content length exceeds 1,000,000 characters
    if len(content) > 1000000:
        print("Content exceeds 1,000,000 characters. Please retry.")
        return None, None, None  # Return None tuple if content is too long
    
    # Return the gathered email details
    return destinations, title, content


def sendEmail(clientSocket, symKey, username):
    """
    Purpose: Send an email from the user to specified recipients.
    Parameters:
        - clientSocket (socket): The socket connected to the server.
        - symKey (bytes): The symmetric key for AES encryption.
        - username (str): Sender's username.
    Return: None
    """
    # Retrieve email details from the user
    destinations, title, content = getEmailDetails()

    # Check if all email details are provided
    if destinations and title and content:
        
        # Structure the email into a dictionary
        email = {
            "From": username,
            "To": destinations,
            "Title": title,
            "Content Length": len(content),
            "Content": content
        }

        # Convert the email dictionary to a JSON string
        email_json = json.dumps(email)
        
        # Send the encrypted email JSON to the server
        clientSocket.send(encryptMessage(email_json, symKey))
        print("The message is sent to the server.")
    
    else:
        # Inform the user that email sending is aborted if details are missing
        print("Email sending aborted.")

def displayInboxList(clientSocket, symKey):
    """
    Purpose: Request and display the list of emails in the user's inbox.
    Parameters:
        - clientSocket (socket): The socket connected to the server.
        - symKey (bytes): The symmetric key for AES encryption.
    Return: None
    """
    # Request the server to send the inbox list
    clientSocket.send(encryptMessage("2", symKey))  # '2' is the menu option for inbox list
    
    # Receive and decrypt the inbox list from the server
    inboxList = decryptMessage(clientSocket.recv(1024), symKey)
    
    # Print the inbox list
    print("Inbox List:\n", inboxList)

def displayEmailContents(clientSocket, symKey):
    """
    Purpose: Request and display the contents of a specific email.
    Parameters:
        - clientSocket (socket): The socket connected to the server.
        - symKey (bytes): The symmetric key for AES encryption.
    Return: None
    """
    # Prompt the user to enter the index of the email they wish to view
    emailIndex = input("Enter the email index you wish to view: ")
    
    # Request the server to send the contents of the specified email
    clientSocket.send(encryptMessage(emailIndex, symKey))
    
    # Receive and decrypt the email content from the server
    emailContent = decryptMessage(clientSocket.recv(1024), symKey)
    
    # Print the email content
    print("Email Content:\n", emailContent)

#------------------------------------------------------------------------------
# Main client function
#------------------------------------------------------------------------------
def client():
    """
    Main client function to handle the connection and communication with the server.
    It handles user authentication and all mail operations.
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

        # Send OK to server
        clientSocket.send(encryptMessage("OK", symKey))
        
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