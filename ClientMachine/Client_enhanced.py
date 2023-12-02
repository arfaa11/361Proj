'''
Student names: - Arfaa Mumtaz
               - Cory Beaunoyer
               - Kevin Esperida
               - Olasubomi Badiru
Instructor name: Mahdi Firoozjaei
Assignment: Secure Mail Transfer Project
Program name: Client_enhanced.py
Program purpose: <TODO>
'''

#------------------------------------------------------------------------------
# Import statements
#------------------------------------------------------------------------------
import socket
import json
import datetime as dt
import os
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
        #print(f"Private key for {username} not found in directory")
        
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

    if destinations and title and content:
        contentLength = str(len(content))
        encryptedContentLength = encryptMessage(contentLength, symKey)
        
        # Send content length first
        clientSocket.send(encryptedContentLength)

        # Prepare the email dictionary
        emailDict = {
            "From": username,
            "To": destinations,
            "Title": title,
            "Content": content
        }

        # Convert the email dictionary to a JSON string
        emailJson = json.dumps(emailDict)
        encryptedEmailJson = encryptMessage(emailJson, symKey)
        # Send the encrypted email JSON to the server
        clientSocket.send(encryptedEmailJson)
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
    # Request the server to send the index prompt
    serverRequest = decryptMessage(clientSocket.recv(1024), symKey)
    # Check if the server request is the email index prompt
    if serverRequest == "the server request email index":
        # Prompt user to enter the email index
        emailIndex = str(input("Enter the email index you wish to view: "))

        # Send the email index to the server
        clientSocket.send(encryptMessage(emailIndex, symKey))
        
        # Receive and decrypt the email content from the server
        emailContent = decryptMessage(clientSocket.recv(1024), symKey)
        
        # Print the email content
        print("Email Content:\n", emailContent)

def checkForMaxAttempts(clientSocket, username):
    """
    Purpose: Check if the user has exceeded the maximum number of attempts.
    Parameters:
        - clientSocket (socket): The socket connected to the server.
        - username (str): The username of the client.
    Return: True if the user is blocked, False otherwise.
    """
    with open("attemptCounter.json", "r") as attemptCounterFile:
        attemptCounter = json.load(attemptCounterFile)

    if username not in attemptCounter:
        return False

    blocked_at = None

    # Check if the user is currently blocked and if 5 minutes have passed
    if attemptCounter[username]['blockedFlag']:
        if os.path.exists("blockedUsers.txt"):
            with open("blockedUsers.txt", "r") as blockedUsersFile:
                # Iterate through each line in the file
                for line in blockedUsersFile:
                    # Check if the line contains the username
                    if username in line:
                        blocked_at_str = line.split(' was blocked at ')[-1]
                        blocked_at = dt.datetime.strptime(blocked_at_str, '%Y-%m-%d %H:%M:%S.%f')
                        break
        
        # Unblock the user if 5 minutes have passed
        if blocked_at and (dt.datetime.now() - blocked_at).total_seconds() > 300:
            attemptCounter[username] = {'attempts': 0, 'blockedFlag': 0}
            # Write the updated attemptCounter to the file
            with open("attemptCounter.json", "w") as attemptCounterFile:
                json.dump(attemptCounter, attemptCounterFile)
            return False
        else:
            # Close the client socket and return True if the user is still blocked
            clientSocket.close()
            return True

    # Increment attempts for unblocked users
    attemptCounter[username]['attempts'] += 1

    # Block the user on the 5th failed attempt
    if attemptCounter[username]['attempts'] >= 5:
        attemptCounter[username] = {'attempts': 0, 'blockedFlag': 1}
        with open("blockedUsers.txt", "a") as blockedUsersFile:
            # Check if the user is already blocked
            if isUserBlocked(username):
                return True
            # Write the username and time to the blockedUsers.txt file
            current_time_str = dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            blockedUsersFile.write(f"{username} was blocked at {current_time_str}\n")
        # Close the client socket and return True if the user is blocked
        clientSocket.close()
        # Print a message to the user
        print("You have exceeded the maximum number of attempts. Please try again in 5 minutes.")
        with open("attemptCounter.json", "w") as attemptCounterFile:
            json.dump(attemptCounter, attemptCounterFile)
        return True

    # Write the updated attemptCounter to the file
    with open("attemptCounter.json", "w") as attemptCounterFile:
        json.dump(attemptCounter, attemptCounterFile)

    # Return False if the user is not blocked
    return False

def isUserBlocked(username):
    """
    Purpose: Check if the user is blocked.
    Parameters:
        - username (str): The username of the client.
    Return: True if the user is blocked, False otherwise."""
    # Check if the blockedUsers.txt file exists
    if os.path.exists("blockedUsers.txt"):
        with open("blockedUsers.txt", "r") as blockedUsersFile:
            # Iterate through each line in the file
            for line in blockedUsersFile:
                # Check if the line contains the username
                if username in line:
                    return True
    return False
#------------------------------------------------------------------------------
# Main client function
#------------------------------------------------------------------------------
def enhancedClient():
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
    
    # Check if the user is blocked
    if isUserBlocked(username):
        print("You are currently blocked. Please try again later.")
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
        print("Invalid username or password.\nTerminating.")
        return
    
    if serverResponse != b"FAILURE":
        symKeyCipher = PKCS1_OAEP.new(privateKey)
        symKey = symKeyCipher.decrypt(encryptedSymKey)

    if serverResponse == b"FAILURE":
        print("Invalid username or password.\nTerminating.")
        checkForMaxAttempts(clientSocket, username) # Check for max attempts
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
    enhancedClient()