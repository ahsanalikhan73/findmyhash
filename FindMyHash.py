#!/usr/bin/env python
import requests
import os
import sys
import hashlib
import base64

class FindMyHash():

	def __init__(self):
		headers = {
			'Accept-Encoding': 'gzip, deflate, sdch',
			'Accept-Language': 'en-US,en;q=0.8',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
			'Referer': 'http://www.wikipedia.org/',
			'Connection': 'keep-alive',
		}
		url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
		self.wordlist = requests.get(url, headers=headers).text

	def clear_screen(self):
		if 'nt' in os.name:
			os.system('cls')
		else:
			os.system('clear')

	def Banner(self):
		banner = '''
			 _______ _           _    _______          _     _            _     
			(_______|_)         | |  (_______)        (_)   (_)          | |    
			 _____   _ ____   __| |   _  _  _ _   _    _______ _____  ___| |__  
			|  ___) | |  _ \ / _  |  | ||_|| | | | |  |  ___  (____ |/___)  _ \ 
			| |     | | | | ( (_| |  | |   | | |_| |  | |   | / ___ |___ | | | |
			|_|     |_|_| |_|\____|  |_|   |_|\__  |  |_|   |_\_____(___/|_| |_|
							  (____/                             
			'''
		print(banner)

	def main_menu(self):
		menu = '''
		{1}-- Hash Encryption
		{2}-- Hash Decryption

		{99}-Exit
		'''
		print(menu)

	def quit(self):
		con = input('Continue [Y/n] -> ')
		if con.upper() == 'N':
			print('\n')
			sys.exit()
		else:
			self.clear_screen()
			self.Banner()
			self.main_menu()
			self.select()

	def encryption(self):
		menu = '''
		\t\t\t   Encryption\n\t\t\t\t\t----------------\n
		{1}-- MD5
		{2}-- SHA-1
		{3}-- SHA-224
		{4}-- SHA-256
		{5}-- SHA-512
		{6}-- Base64
	
		\n\n'''
		try:
			print(menu)
			choice = int(input("root~# "))
			hash = input('\nEnter Something To Encrypt : ')
			if choice == 1:
				print('\n\tMD5  -->   ' + hashlib.md5(hash.encode()).hexdigest() + '\n\n')
				self.quit()
			elif choice == 2:
				print('\n\tSHA-1  -->   ' + hashlib.sha1(hash.encode()).hexdigest() + '\n\n')
				self.quit()
			elif choice == 3:
				print('\n\tSHA-224  -->   ' + hashlib.sha224(hash.encode()).hexdigest() + '\n\n')
				self.quit()
			elif choice == 4:
				print('\n\tSHA-256  -->   ' + hashlib.sha256(hash.encode()).hexdigest() + '\n\n')
				self.quit()
			elif choice == 5:
				print('\n\tSHA-512  -->   ' + hashlib.sha512(hash.encode()).hexdigest() + '\n\n')
				self.quit()
			elif choice == 6:
				encoded_string = base64.b64encode(str.encode(hash))		# Return Bytes
				print('\n\tBase64  -->   ' + encoded_string.decode('utf-8') + '\n\n')	# Convert Bytes to Strings
				self.quit()

		except KeyboardInterrupt:
			print('\n[!] Exitting ...\n')

		self.quit()

	def decryption(self):
		menu = '''
		\t\t\t   Decryption\n\t\t\t\t\t----------------\n
		{1}-- MD5
		{2}-- SHA-1
		{3}-- SHA-224
		{4}-- SHA-256
		{5}-- SHA-512
		{6}-- Base64
	
		\n\n'''
		try:
			print(menu)
			choice = int(input("root~# "))
			hashvalue = input('\nEnter Hash Value To Decrypt : ')
			if choice == 1:
				for password in self.wordlist.split('\n'):
					hash = hashlib.md5(password.encode()).hexdigest()
					if hash == hashvalue:
						print('\nThe Password is --> ' + password + '\n\n')
						self.quit()
					else:
						pass

				print('\nPassword Not In Wordlist ...\n\n')
				self.quit()

			elif choice == 2:
				for password in self.wordlist.split('\n'):
					hash = hashlib.sha1(password.encode()).hexdigest()
					if hash == hashvalue:
						print('\nThe Password is --> ' + password + '\n\n')
						self.quit()
					else:
						pass

				print('\nPassword Not In Wordlist ...\n\n')
				self.quit()

			elif choice == 3:
				for password in self.wordlist.split('\n'):
					hash = hashlib.sha224(password.encode()).hexdigest()
					if hash == hashvalue:
						print('\nThe Password is --> ' + password + '\n\n')
						self.quit()
					else:
						pass

				print('\nPassword Not In Wordlist ...\n\n')
				self.quit()

			elif choice == 4:
				for password in self.wordlist.split('\n'):
					hash = hashlib.sha256(password.encode()).hexdigest()
					if hash == hashvalue:
						print('\nThe Password is --> ' + password + '\n\n')
						self.quit()
					else:
						pass

				print('\nPassword Not In Wordlist ...\n\n')
				self.quit()

			elif choice == 5:
				for password in self.wordlist.split('\n'):
					hash = hashlib.sha512(password.encode()).hexdigest()
					if hash == hashvalue:
						print('\nThe Password is --> ' + password + '\n\n')
						self.quit()
					else:
						pass

				print('\nPassword Not In Wordlist ...\n\n')
				self.quit()

			elif choice == 6:
				decoded_string = base64.b64decode(str.encode(hashvalue))	# return Bytes
				print('\n\tBase64  -->   ' + decoded_string.decode('utf-8') + '\n\n')	# convert bytes to strings
				self.quit()

		except KeyboardInterrupt:
			print('\n[!] Exitting ...\n')

		self.quit()

	def  select(self):
		try:
			choice = int(input("root~# "))
			if choice == 1:
				self.clear_screen()
				print('\n')
				self.encryption()	# function call
				self.quit()

			elif choice == 2:
				self.clear_screen()
				print('\n')
				self.decryption()	#function call
				self.quit()

			elif choice == 99:
				print('\n')
				sys.exit()

		except KeyboardInterrupt:
			print('\n[!] Exitting ...\n')

		self.quit()

	def main(self):
		self.clear_screen()
		self.Banner()
		self.main_menu()
		self.select()


if __name__ == '__main__':
	findmyhash = FindMyHash()
	findmyhash.main()