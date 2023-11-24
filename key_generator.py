'''
Student names: - Arfaa Mumtaz
               - Cory Beaunoyer
               - Kevin Esperida
               - Olasubomi Badiru
Instructor name: Mahdi Firoozjaei
Assignment: Secure Mail Transfer Project
Program name: key_generator.py
Program purpose: <TODO>
'''

import os
from Crypto.PublicKey import RSA

def generateKeys(username, outputDir):
    # Generate a new RSA key pair with a key length of 2048 bits
    key = RSA.generate(2048)

    # Export the private key as a PEM-formatted string
    privKey = key.export_key()

    # Export the public key as a PEM-formatted string
    pubKey = key.publickey().export_key()

    # Save the private key to a file with the username as part of the filename
    privKeyFilename = os.path.join(outputDir, f'{username}_private.pem')
    with open(privKeyFilename, 'wb') as privKeyFile:
        privKeyFile.write(privKey)

    # Save the public key to a file with the username as part of the filename
    pubKeyFilename = os.path.join(outputDir, f'{username}_public.pem')
    with open(pubKeyFilename, 'wb') as pubKeyFile:
        pubKeyFile.write(pubKey)

if __name__ == "__main__":
    # Specify the server machine directory where server keys will be stored
    serverDir = "ServerMachine"  

    # Create the server machine directory if it doesn't exist
    if not os.path.exists(serverDir):
        os.mkdir(serverDir)

    # Generate key pairs for the server in the server machine directory
    generateKeys("server", serverDir)

    # Specify the client machine directory where client keys will be stored
    clientDir = "ClientMachine" 

    # Create the client machine directory if it doesn't exist
    if not os.path.exists(clientDir):
        os.mkdir(clientDir)

    # List of usernames for which key pairs will be generated (excluding "server")
    clientUsernames = ["client1", "client2", "client3", "client4", "client5"]

    # Generate key pairs for known clients in the client machine directory
    for username in clientUsernames:
        generateKeys(username, clientDir)

    # Copy the server's public key to the client machine directory
    serverPubKeySrc = os.path.join(serverDir, "server_public.pem")
    serverPubKeyDest = os.path.join(clientDir, "server_public.pem")
    with open(serverPubKeySrc, 'rb') as srcFile, open(serverPubKeyDest, 'wb') as destFile:
        destFile.write(srcFile.read())

    # Copy all client public keys to the server machine directory
    for username in clientUsernames:
        clientPubKeySrc = os.path.join(clientDir, f'{username}_public.pem')
        clientPubKeyDest = os.path.join(serverDir, f'{username}_public.pem')
        with open(clientPubKeySrc, 'rb') as srcFile, open(clientPubKeyDest, 'wb') as destFile:
            destFile.write(srcFile.read())