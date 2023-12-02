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
    Purpose: Check if the user has exceeded the maximum number of attempts. If
        yes, close the connection for a given period of time
    Parameters:
        - clientSocket (socket): The socket connected to the server.
        - username (str): The username of the client.
    Return:
    """
    # Load the attempt counter data
    with open("attemptCounter.json", "r") as attemptCounterFile:
        attemptCounter = json.load(attemptCounterFile)

    # Check if the username is already in the attemptCounter
    if username not in attemptCounter:
        attemptCounter[username] = {'attempts': 0, 'blockedTime': None}

    # Check if the user is currently blocked and if 5 minutes have passed
    if attemptCounter[username]['blockedTime']:
        blocked_time = dt.datetime.fromisoformat(attemptCounter[username]['blockedTime'])
        current_time = dt.datetime.now()
        # Calculate the difference in minutes
        difference_in_minutes = (current_time - blocked_time).total_seconds() / 60

        if difference_in_minutes > 5:
            # Unblock the user
            attemptCounter[username] = {'attempts': 0, 'blockedTime': None}
            # Remove the user from the blockedUsers.txt file
            with open("blockedUsers.txt", "r") as file:
                lines = file.readlines()
            with open("blockedUsers.txt", "w") as file:
                for line in lines:
                    if line.strip("\n") != username:
                        file.write(line)
        else:
            # User is still blocked
            clientSocket.close()
            print("You are currently blocked. Please try again later.")
            return True

    # Increment the number of attempts
    attemptCounter[username]['attempts'] += 1

    # Check if the number of attempts is greater than 5
    if attemptCounter[username]['attempts'] > 5:
        # Block the user
        attemptCounter[username]['attempts'] = 0
        attemptCounter[username]['blockedTime'] = dt.datetime.now().isoformat()
        # Write to blockedUsers.txt
        with open("blockedUsers.txt", "a") as blockedUsersFile:
            blockedUsersFile.write(f"{username}\n")
        # Close the client socket
        clientSocket.close()
        print("You have exceeded the maximum number of attempts. Please try again later.")
        return True
    else:
        # Write the new data to the attemptCounter.json file
        with open("attemptCounter.json", "w") as attemptCounterFile:
            json.dump(attemptCounter, attemptCounterFile)
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
    
    # Check if the user has exceeded the maximum number of attempts
    if checkForMaxAttempts(clientSocket, username):
        # Close the client socket
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