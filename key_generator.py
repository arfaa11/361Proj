from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

#Key Generator
filenames = [
	['server_private.pem','server_public.pem'],
	['client1_private.pem','client1_public.pem'],
	['client2_private.pem','client2_public.pem'],
	['client3_private.pem','client3_public.pem'],
	['client4_private.pem','client4_public.pem'],
	['client5_private.pem','client5_public.pem'],
]

machIndex = 0
while machIndex < len(filenames):
	print(filenames[machIndex])
	# Generate private and public keys
	key = RSA.generate(2048)
	private_key = key.export_key()
	print(private_key)
	public_key = key.publickey().export_key()
	print(public_key)
	
	with open(filenames[machIndex][0], 'wb') as file:
		#Write the bytes to the file
		file.write(private_key)
	
	with open(filenames[machIndex][1], 'wb') as file:
		file.write(public_key)
	
	machIndex += 1
	
	
	
