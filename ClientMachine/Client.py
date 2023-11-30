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


#------------------------------------------------------------------------------
# Helper functions for Email interactions
#------------------------------------------------------------------------------

def makeEmail(source,message, title, dest):
    '''
    Input: 
        source: string
        message: string
        title: string
        dest: list of strings containing destinations
    Output:
        return full edited message or -1 if the message is too long 
    '''
    dest  = dest.join(";")
    length = len(message)
    if length <= 1000000:
        return (f"\nFrom: {source}\nTo: {dest}\nTitle: {title}"
                 "\nContent Length: {length}\nContent:\n{message}")
    return

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
    encryptedUser = cipher.encrypt(username.encode())
    encryptedPass = cipher.encrypt(password.encode())
    #print("gotten password and user\n")

    # Send the encrypted username and password to the server
    clientSocket.send(encryptedUser)
    #print("sent username")

    clientSocket.send(encryptedPass)
    #print("sent password")

    
    # Receive and decrypt the symmetric key from the server
    encryptedSymKey = clientSocket.recv(1024)
    privateKey = loadPrivateKey(username)
    if privateKey is None:
        #print("Error: Private key not found.")
        return

    symKeyCipher = PKCS1_OAEP.new(privateKey)
    
    symKey = symKeyCipher.decrypt(encryptedSymKey)
    #print(symKey)

    # Check for invalid username or password response
    if symKey == b"Invalid username or password":
        print("Invalid username or password.\nTerminating.")
        clientSocket.close()
        return

    if symKey is not None:
        print("Authentication successful.")
        # Send an acknowledgment message
        clientSocket.send(encryptMessage("OK", symKey))

        menu = decryptMessage(clientSocket.recv(1024),symKey)
        choice = input(menu)

        while choice != '0':
            
            match choice:
                case '1':
                    ''' Sub protocol 1'''
                    pass
                case '2':
                    ''' sub protocol 2'''
                    pass
                case 1:
                    ''' su protocol 3'''
                    pass
                case _:
                    ''' default is break from loop and close'''
                    break
            menu = decryptMessage(clientSocket.recv(1024),symKey)
            choice = input(menu)


        #begin while loop

        ''' <TODO> '''
        # I have not yet worked on the main client-server interaction
        # loop yet. I want to be sure that this version of the code is
        # clear/easy to understand and track for you guys, and we will
        # work on any changes, and all further additions together.

    # Close the client socket when done
    clientSocket.close()
#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# Run program
#------------------------------------------------------------------------------
if __name__ == "__main__":
    client()
