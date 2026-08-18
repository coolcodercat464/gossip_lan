# basic sockets
import socket
from threading import Thread
import threading

# basic encryption (dh + aes)
from Cryptodome.Util.number import getPrime # python3.11 -m pip install pycryptodomex
from Cryptodome import Random
from Cryptodome.Cipher import AES

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

import secrets
import base64
import hashlib
from io import BytesIO
import PyPDF2

# misc
import datetime
import builtins
import os

# queues
from collections import deque
import queue # more thread safe apparently

# database and authentication
from bs4 import BeautifulSoup # pip install beautifulsoup4
import json

# gui
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

# thread-safe print
print_lock = threading.Lock()
original_print = builtins.print
def custom_print(*args):
    with print_lock: original_print(*args)
builtins.print = custom_print

####################
## FILES
####################

# get data of pdf with all metdata removed
def clean_pdf(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            writer = PyPDF2.PdfWriter()
            
            # Copy pages without metadata
            for page in reader.pages:
                writer.add_page(page)
                
            # Write to a bytes buffer
            buffer = BytesIO()
            writer.write(buffer)
            buffer.seek(0)

        data = buffer.read()
        hashed = hashlib.sha256(data).hexdigest()
        return data, hashed
    else:
        return '', ''

####################
## CRYPTOGRAPHY
####################

# aes gcm encryption class
class GCM:
    def __init__(self, secretKey):
        self.secretKey = secretKey

    def encrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        cipher = AES.new(aesKey, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
        return cipher.nonce + ciphertext + tag

    def decrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        nonce = msg[:16]
        tag = msg[-16:]
        msg = msg[16:-16]

        cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(msg, tag).decode()
        except ValueError:
            print("Decryption failed: Key incorrect or message tampered with")
            return False

####################
## AUTHENTICATION
####################

def get_local_ip():
    try:
        # Create a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to a remote server (e.g., Google DNS)
        s.connect(('8.8.8.8', 80))
        # Get the local socket name (IP and port)
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        return f"Error: {e}"

# load local ssh public and private keys
# generated with 'ssh-keygen -t ed25519'
with open('key.pub', 'rb') as key_file:
    public_key_bytes = key_file.read()

self_authentication_public_key_string = public_key_bytes.decode()
self_authentication_public_key = serialization.load_ssh_public_key(public_key_bytes)
self_hostname = socket.gethostname()
self_ip_address = get_local_ip()

print("WELCOME TO P2P LAN")
print("Your username is:", self_hostname)
print("You can change this by changing your hostname.")

# authenticate user by asking for password to decrypt private key
while True:
    print()
    password = input("Enter your SSH key password: ").encode()
    try:
        with open('key', 'rb') as key_file:
            self_authentication_private_key = serialization.load_ssh_private_key(key_file.read(), password=password)
        break
    except Exception as e:
        print("ERROR. PLEASE TRY AGAIN.")
        print(e)

# sign challenge
def sign(message):
    return self_authentication_private_key.sign(message)

def verify(public_key, signature, message):
    # parse it
    if type(public_key) == str:
        public_key = serialization.load_ssh_public_key(public_key.strip().encode("utf-8"))

    # verify signature
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False

####################
## SOCKETS
####################
   
# send message + byte size
def sendall(this_socket, content):
    try:
        address = this_socket.getpeername()
        with dict_lock_socket_locks:
            print(address, all_socket_locks)
            this_socket_lock = all_socket_locks[address]
        
        with this_socket_lock:
            print("---Sending Information---")
            byte_size = str(len(content))
            msg = byte_size + ' '

            print(msg, content)
            this_socket.sendall(msg.encode() + content)
    except Exception as e:
        print("ERROR (sendall) FOR ADDRESS", this_socket.getpeername()[0], ":", e)
        threadsafe_showinfo("Error (sendall) for address " + this_socket.getpeername()[0], e)

# receive all (no matter byte size)
def recvall(this_socket, chunk_size=1024):
    try:
        address = this_socket.getpeername()
        with dict_lock_socket_locks:
            print(address, all_socket_locks)
            this_socket_lock = all_socket_locks[address]
        
        with this_socket_lock:
            print("---Waiting for Message---")
            first_chunk = this_socket.recv(chunk_size)
            # connection terminated
            if not first_chunk:
                return False

            space_enc = ' '.encode()
            splitted = first_chunk.split(space_enc)
            print(splitted[0])
            byte_size = int(splitted[0].decode())
            everything_else = space_enc.join(splitted[1:])

            if len(everything_else) == int(byte_size):
                return everything_else
            else:
                all_chunks = everything_else
                byte_size -= len(everything_else)
                while byte_size > 0:
                    next_chunk = this_socket.recv(chunk_size)
                    # connection terminated
                    if not next_chunk:
                        return False
                    all_chunks += next_chunk
                    byte_size -= len(next_chunk)

                return all_chunks
    except Exception as e:
        print("ERROR (recvall) FOR ADDRESS", this_socket.getpeername()[0], ":", e)
        threadsafe_showinfo("Error (recvall) for address " + this_socket.getpeername()[0], e)

####################
## LISTENER
####################

# list of all server sockets
list_lock_all_servers = threading.Lock()
list_lock_all_requests = threading.Lock()
list_lock_all_requests_comments = threading.Lock()
dict_lock_servers = threading.Lock()
dict_lock_socket_locks = threading.Lock()
dict_lock_ciphers = threading.Lock()
dict_lock_initiated_widgets = threading.Lock()
dict_lock_untrusted_widgets = threading.Lock()
dict_lock_untrusted_keys = threading.Lock()
dict_lock_download_requests = threading.Lock()

all_servers = []
all_requests = []
all_requests_comments = []
servers = dict()
all_socket_locks = dict()
ciphers = dict()
initiated_widgets = dict()
untrusted_widgets = dict()
untrusted_keys = dict()
download_requests = dict()

# process for each client
def clientHandler(communication_socket, address):
    global untrusted_list
    try:
        print('CLIENT HANDLER CREATED FOR ADDRESS', address)

        # wait for client message and close socket if connection terminated
        def get_message():
            content = recvall(communication_socket)
            # connection terminated
            if not content:
                print("CONNECTION CLOSED")
                communication_socket.close()
                return False
            else:
                print('---Message Received from client at', address, '!---')
                #print(content)
                return content

        # dh initialisation
        P = getPrime(2048)                     # 2048 bit prime for security
        G = 5                                  # generator doesn't have to be large
        dh_private_key = secrets.randbelow(2**512) # private key should be at least 256 bits

        # identify addresses
        address, _ = address

        authenticated_self = False
        authenticated_client = False
        client_authentication_public_key = None
        challenge = None
        # authentication challenges
        print('---AUTHENTICATION FOR CLIENT', address, '---')
        while not (authenticated_self and authenticated_client):
            # take in new messages
            message = get_message()
            if not message: raise Exception("Client Disconnected")

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # challenges
                if command == b'sign':
                    signature = sign(content)
                    sendall(communication_socket, signature)
                elif command == b'valid':
                    authenticated_self = True
                    sendall(communication_socket, 'okay'.encode())
                elif command == b'hello':
                    client_authentication_public_key = content.decode()
                    challenge = secrets.token_bytes(32)
                    sendall(communication_socket, challenge)
                elif command == b'invalid':
                    # exit if authentication fails
                    raise Exception("Authentication failed")
                elif command == b'signed':
                    # ensure we have their public key
                    if client_authentication_public_key == None:
                        challenge = secrets.token_bytes(32)
                        sendall(communication_socket, challenge)
                    else:
                        # verify signature and exit if invalid
                        signature = content
                        if verify(client_authentication_public_key, signature, challenge):
                            sendall(communication_socket, 'valid'.encode())
                            authenticated_client = True
                        else:
                            sendall(communication_socket, 'invalid'.encode())
                            raise Exception("Authentication failed")
       
        # authentication complete. create bidirectional connection
        data = read_connections()

        if address in data.keys() and data[address] == client_authentication_public_key:
            # trusted
            add_sender(address, client_authentication_public_key, True)
        else:
            # untrusted
            add_sender(address, client_authentication_public_key, False)
            with dict_lock_untrusted_keys:
                untrusted_keys[address] = client_authentication_public_key

        encrypted = False
        # dh key exchange
        print('---DH KEY EXCHANGE FOR CLIENT', address, '---')
        while not encrypted:
            # take in new messages
            message = get_message()
            if not message: raise Exception("Client Disconnected")

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # dh exchanges
                if command == b'prime':
                    sendall(communication_socket, str(P).encode())
                elif command == b'generator':
                    sendall(communication_socket, str(G).encode())
                elif command == b'exchange':
                    try:
                        clientKey = int(content.decode())
                        serverKey = pow(G, dh_private_key, P)
                        secretKey = pow(clientKey, dh_private_key, P)

                        byteKey = secretKey.to_bytes((secretKey.bit_length() + 7)//8, byteorder='big')
                        encrypted = byteKey
                       
                        sendall(communication_socket, str(serverKey).encode())
                    except:
                        sendall(communication_socket, 'invalid'.encode())

        # initialise AES cipher
        cipher = GCM(encrypted)

        print('---MAINTAING CONNECTION FOR CLIENT', address, '---')

        while True:
            # take in new messages
            message = get_message()
            if not message: raise Exception("Client Disconnected")

            # split into command and content
            splitted = message.split(b':::')

            if len(splitted) > 0:
                command = splitted[0]
                content = b':::'.join(splitted[1:])

                # add message
                if command == b'message':
                    # msg = 'message'.encode() + ':::'.encode() + channel.get().encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(text) + ':::'.encode() + time.encode() + ':::'.encode() + sign(text.encode() + time.encode())

                    channel = content.split(b':::')[0].decode()

                    sender_public_key = cipher.decrypt(content.split(b':::')[1])

                    text = cipher.decrypt(content.split(b':::')[2])
                    
                    time = content.split(b':::')[3].decode()

                    signature = content.split(b':::')[4]

                    if verify(sender_public_key, signature, text.encode() + time.encode()):
                        # prevent duplicates from blowing up
                        if not message_exists(text, sender_public_key, channel, time):
                            add_message(sender_public_key, text, channel, time)
                            show_messages()

                            print('---SENDING MESSAGE TO ALL SERVERS---')
                            with dict_lock_servers:
                                for a, client_socket in servers.items():
                                    print('ADDRESS:', a)
                        
                                    # encrypt and sign message
                                    cipher2 = ciphers[a]
                        
                                    msg = 'message'.encode() + ':::'.encode() + channel.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(text) + ':::'.encode() + time.encode() + ':::'.encode() + signature
                                    sendall(client_socket, msg)

                    else:
                        print("SIGNATURE INVALID")

                # resources query
                elif command == b'query':
                    # msg = 'query'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(label) + ':::'.encode() + time.encode() + ':::'.encode() + sign(label.encode() + time.encode())

                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])
                    
                    label = cipher.decrypt(content.split(b':::')[2])
                    
                    time = content.split(b':::')[3].decode()
                    
                    signature = content.split(b':::')[4]

                    if verify(sender_public_key, signature, label.encode() + time.encode()):
                        # prevent duplicates from blowing up
                        with list_lock_all_requests:
                            if (sender_public_key, label, time) not in all_requests:
                                all_requests.append((sender_public_key, label, time))

                                # check if you have resource
                                _, data_by_label, _ = read_resources()

                                resources_found = []
                                for l in data_by_label.keys():
                                    if label in l:
                                        for r in data_by_label[l]:
                                            resources_found.append(r)

                                if len(resources_found) > 0:
                                    resources_string = json.dumps(resources_found)

                                    t = threading.Thread(target=add_sender_for_resource, args=('response', sender_ip_address, sender_public_key, False, resources_string))
                                    t.start()

                                print('---SENDING MESSAGE TO ALL SERVERS---')
                                with dict_lock_servers:
                                    for a, client_socket in servers.items():
                                        print('ADDRESS:', a)
                            
                                        # encrypt and sign message
                                        cipher2 = ciphers[a]

                                        msg = 'query'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(label) + ':::'.encode() + time.encode() + ':::'.encode() + signature
                                        sendall(client_socket, msg)
                    else:
                        print("SIGNATURE INVALID")

                # resources query by hash
                elif command == b'query_by_hash':
                    # msg = 'query_by_hash'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + sign(hashed.encode())

                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])

                    hashed = cipher.decrypt(content.split(b':::')[2])
                    
                    time = content.split(b':::')[3].decode()
                    
                    signature = content.split(b':::')[4]

                    if verify(sender_public_key, signature, hashed.encode()):
                        # prevent duplicates from blowing up
                        with list_lock_all_requests:
                            if (sender_public_key, hashed, time) not in all_requests:
                                all_requests.append((sender_public_key, hashed, time))

                                # check if you have resource
                                _, _, data_by_hash = read_resources()

                                if hashed in data_by_hash.keys():
                                    resources_found = data_by_hash[hashed]
                                    resources_string = json.dumps(resources_found)

                                    t = threading.Thread(target=add_sender_for_resource, args=('response', sender_ip_address, sender_public_key, False, resources_string))
                                    t.start()

                                print('---SENDING MESSAGE TO ALL SERVERS---')
                                with dict_lock_servers:
                                    for a, client_socket in servers.items():
                                        print('ADDRESS:', a)
                            
                                        # encrypt and sign message
                                        cipher2 = ciphers[a]

                                        msg = 'query_by_hash'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + signature
                                        
                                        sendall(client_socket, msg)
                    else:
                        print("SIGNATURE INVALID")
                # comments query
                elif command == b'query_comments':
                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])

                    resource_hash = cipher.decrypt(content.split(b':::')[2])
                    
                    time = content.split(b':::')[3].decode()
                    
                    signature = content.split(b':::')[4]

                    if verify(sender_public_key, signature, resource_hash.encode() + time.encode()):
                        # prevent duplicates from blowing up
                        with list_lock_all_requests_comments:
                            if (sender_public_key, resource_hash, time) not in all_requests_comments:
                                all_requests_comments.append((sender_public_key, resource_hash, time))

                                # check if you have resource
                                _, data_by_hash, _ = read_resources(resource_type='comment')

                                if resource_hash in data_by_hash.keys():
                                    comments_string = json.dumps(data_by_hash[resource_hash])

                                    t = threading.Thread(target=add_sender_for_resource, args=('response_comment', sender_ip_address, sender_public_key, False, comments_string))
                                    t.start()

                                print('---SENDING MESSAGE TO ALL SERVERS---')
                                with dict_lock_servers:
                                    for a, client_socket in servers.items():
                                        print('ADDRESS:', a)
                            
                                        # encrypt and sign message
                                        cipher2 = ciphers[a]

                                        # TODO - implement time-to-live, so message is discarded after 10 seconds, say. this way, theres a cooldown between requests the client can make
                                        msg = 'query_comments'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(resource_hash) + ':::'.encode() + time.encode() + ':::'.encode() + signature
                                        sendall(client_socket, msg)
                    else:
                        print("SIGNATURE INVALID")
                        
                # get response from query
                elif command == b'response':
                    # msg = 'response'.encode() + ':::'.encode() + cipher.encrypt(resources_string)

                    resources_string = cipher.decrypt(content)
                    resources_obj = json.loads(resources_string)
                    
                    with list_resources_lock:
                        for resource in resources_obj:
                            resource_pub_key = resource['user'].strip()
                            signature = bytes.fromhex(resource['signature'].strip())
                            if verify(resource_pub_key, signature, resource['label'].encode() + resource['text'].encode()):
                                all_resources.append(resource)
                                item = 'QUERY RESPONSE: ' + resource['label'] + ' (' + parse_user_key(resource['user']) + ')'
                                insert_to_resources_listbox(item)
                            else:
                                print("INVALID SIGNATURE. UH OH.")

                # get response from comment query
                elif command == b'response_comment':
                    comments_string = cipher.decrypt(content)
                    comments_obj = json.loads(comments_string)
                    
                    with list_resources_lock:
                        for comment in comments_obj:
                            comment_pub_key = comment['user']
                            signature = bytes.fromhex(comment['signature'])
                            if verify(comment_pub_key, signature, comment['label'].encode() + comment['text'].encode()):
                                all_resources.append(comment)
                                item = 'COMMENT QUERY RESPONSE: ' + comment['label'] + ' (' + parse_user_key(comment['user']) + ')'
                                insert_to_resources_listbox(item)
                            else:
                                print("INVALID SIGNATURE. UH OH.")

                # request to send a file over
                elif command == b'download':
                    # msg = 'download'.encode() + ':::'.encode() + cipher.encrypt(hashed)

                    resource_hash = cipher.decrypt(content.split(b':::')[0])
                    print(resource_hash)

                    # check if you have resource
                    _, _, data_by_hash = read_resources()
                    print(data_by_hash)

                    if resource_hash in data_by_hash.keys():
                        resource = data_by_hash[resource_hash][0]
                        
                        path = resource['filename']
                        print(path)
                        file, hashed = clean_pdf(path)
                        print(file, hashed)

                        # ensure file exists
                        if hashed != '':
                            with dict_lock_servers:
                                for a, client_socket in servers.items():
                                    if a == communication_socket.getpeername()[0]:
                                        cipher2 = ciphers[a]
                                        sendall(client_socket, 'download_response:::'.encode() + file)

                # get response from download request
                elif command == b'download_response':
                    file = content
                    hashed = hashlib.sha256(content).hexdigest()

                    with dict_lock_download_requests:
                        hashed = download_requests[address]
                        del download_requests[address]

                    path = filename_entry.get()
                    
                    with open(path, "wb") as f:
                        f.write(file)

                    _, hashed = clean_pdf(path)

                    threadsafe_showinfo("Download Successful!", "File at " + path + " with content hash " + hashed)

    except Exception as e:
        print("ERROR (clientHandler) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (clientHandler) for address " + address, e)

    finally:
        print('---CLOSING CONNECTION TO CLIENT', address, '---')
        communication_socket.close()
        cleanup(address)

# listen for clients
def listen():
    print('LISTENING...')

    # set up server
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listener.bind(('0.0.0.0', 65432))
    listener.listen(50)

    print("Server set up :D")
   
    while True:
        try:
            communication_socket, address = listener.accept()

            print("CONNECTION DETECTED FROM:", address)
            print(dict_lock_socket_locks)

            with dict_lock_socket_locks:
                all_socket_locks[address] = threading.Lock()

            # make new thread for each client
            client = threading.Thread(target=clientHandler, args=(communication_socket, address,))
            client.start()
        except Exception as e:
            print("LISTENER ERROR:", e)
            threadsafe_showinfo("Error (listen)!", e)

####################
## GENERAL CONNECTIONS
####################

# remove socket from lists/dictionaries after connection is closed
def cleanup(address):
    print("CLEANUP CONNECTION FOR", address)
    with dict_lock_servers:
        if address in servers.keys():
            servers[address].close()
            del servers[address]
    with list_lock_all_servers:
        if address in all_servers:
            all_servers.remove(address)
    with dict_lock_ciphers:
        if address in ciphers.keys():
            del ciphers[address]

    with dict_lock_untrusted_widgets:
        if address in untrusted_widgets:
            untrusted_widgets[address].config(bg='red')
    with dict_lock_initiated_widgets:
        if address in initiated_widgets:
            initiated_widgets[address].config(bg='red')
    print("SERVERS:", all_servers)

# remove widget from tkinter display
def destroy_widget(address):
    try:
        with list_lock_all_servers:
            if address not in all_servers:
                with dict_lock_untrusted_widgets:
                    if address in untrusted_widgets:
                        untrusted_widgets[address].master.destroy()
                        del untrusted_widgets[address]
                with dict_lock_initiated_widgets:
                    if address in initiated_widgets:
                        initiated_widgets[address].master.destroy()
                        del initiated_widgets[address]
    except Exception as e:
        print("ERROR (destroy_widget) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (destroy_widget) for address " + address, e)

# toggle trust
def toggle_trust(address):
    try:
        data = read_connections()
        
        if address in data.keys():
            # untrust address
            remove_connection(address)
            threadsafe_showinfo("Untrusted!", "This address has been removed from the trusted list (connections.xml).")
        else:
            # trust address
            with dict_lock_untrusted_keys:
                if address in untrusted_keys.keys():
                    key = untrusted_keys[address]
                    add_connection(address, key)
                    threadsafe_showinfo("Trusted!", "This address has been added to the trusted list (connections.xml).")
    except Exception as e:
        print("ERROR (toggle_trust) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (toggle_trust) for address " + address, e)

####################
## SENDER
####################

# sending socket to all trusted peers
def spawn_senders():
    try:
        data = read_connections()

        print('SPAWNING SENDERS TO:')
        for address, key in data.items():
            add_sender(address, key, True)
    except Exception as e:
        print("ERROR (spawn_senders):", e)
        threadsafe_showinfo("Error (spawn_senders)", e)

# gui helper function
def add_sender_gui(address, key, trusted):
    # gui stuff
    if trusted:
        with dict_lock_initiated_widgets:
            text = address + ' (' + parse_user_key(key) + ')'
            
            child = tk.Frame(trusted_list)
            child.grid(padx=10, pady=10)
            
            widget = tk.Label(child, text=text, wraplength=100, bg='yellow')
            widget.grid(row=0, column=0, rowspan=2)
            
            initiated_widgets[address] = widget
    else:
        with dict_lock_untrusted_widgets:
            text = address + ' (' + parse_user_key(key) + ')'
            
            child = tk.Frame(untrusted_list)
            child.grid(padx=10, pady=10)
            
            widget = tk.Label(child, text=text, wraplength=100, bg='yellow')
            widget.grid(row=0, column=0, rowspan=2)
            
            untrusted_widgets[address] = widget
    
    reset = tk.Button(child, text='R', command=lambda: add_sender(address, key, trusted))
    reset.grid(row=0, column=1)

    close = tk.Button(child, text='C', command=lambda: cleanup(address))
    close.grid(row=0, column=2)

    remove = tk.Button(child, text='X', command=lambda: destroy_widget(address))
    remove.grid(row=1, column=1)

    trust = tk.Button(child, text='T', command=lambda: toggle_trust(address))
    trust.grid(row=1, column=2)

    return widget

# create a single sender socket + widgets + append to servers list
def add_sender(address, key, trusted):
    try:
        print('ADDING SENDER TO ADDRESS:', address)

        continue_logic = False
        with list_lock_all_servers:
            if address not in all_servers:
                continue_logic = True

        if continue_logic:
            destroy_widget(address)
            all_servers.append(address)
            widget = add_sender_gui(address, key, trusted)

            # create the actual socket
            server = threading.Thread(target=create_sender, args=(address, key, widget, trusted))
            server.start()
                
    except Exception as e:
        print("ERROR (add_sender) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (add_sender) for address " + address, e)

# create sender and immediately send resource when connection is ready
def add_sender_for_resource(response_type, address, key, trusted, resources_string):
    try:
        print('ADDING SENDER (FOR RESOURCE) TO ADDRESS:', address)
        
        continue_logic = False
        with list_lock_all_servers:
            if address not in all_servers:
                continue_logic = True

        if continue_logic:
            destroy_widget(address)
            all_servers.append(address)
            widget = add_sender_gui(address, key, trusted)

            # create the actual socket
            client_socket, cipher = create_sender(address, key, widget, trusted)

            msg = response_type.encode() + ':::'.encode() + cipher.encrypt(resources_string)
            sendall(client_socket, msg)
        else:
            exists = False
            with dict_lock_servers:
                if address in servers.keys():
                    client_socket = servers[address]
                    
                    with dict_lock_ciphers:
                        if address in ciphers.keys():
                            cipher = ciphers[address]

                            exists = True

            if exists:
                msg = response_type.encode() + ':::'.encode() + cipher.encrypt(resources_string)
                sendall(client_socket, msg)
                
    except Exception as e:
        print("ERROR (add_sender_for_resource) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (add_sender_for_resource) for address " + address, e)

# create the sender socket and maintain the connection
def create_sender(address, server_public_key, widget, trusted):
    try:
        # server parameters
        server = (address, 65432)

        # dh private key
        dh_private_key = secrets.randbelow(2**256)
   
        # connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(server)
        
        with dict_lock_socket_locks:
            all_socket_locks[server] = threading.Lock()

        # authenticate server
        print('---AUTHENTICATING WITH SERVER', address, '---')
        hello = 'hello:::' + self_authentication_public_key_string
        sendall(client_socket, hello.encode())

        challenge = recvall(client_socket)
        signature_msg = 'signed:::'.encode() + sign(challenge)
        sendall(client_socket, signature_msg)

        response = recvall(client_socket).decode()
        if response == 'invalid': raise("Authentication failed")
        challenge = secrets.token_bytes(32)
        challenge_msg = 'sign:::'.encode() + challenge
        sendall(client_socket, challenge_msg)

        signature = recvall(client_socket)
        if verify(server_public_key, signature, challenge) == False:
            sendall(client_socket, 'invalid'.encode())
            raise("Authentication failed")
        sendall(client_socket, 'valid'.encode())
        okay = recvall(client_socket)
        print(okay)

        # encrypt connection: diffie hellman
        print('---DH HANDSHAKE WITH SERVER', address, '---')
        # get prime
        sendall(client_socket, 'prime'.encode())
        P = int(recvall(client_socket).decode())

        # get generator
        sendall(client_socket, 'generator'.encode())
        G = int(recvall(client_socket).decode())

        clientKey = pow(G, dh_private_key, P) # modular exponentiation is more efficient. Before, it took forever.

        # exchange keys
        msg = "exchange:::" + str(clientKey)
        sendall(client_socket, msg.encode())
        key = int(recvall(client_socket).decode())

        # calculate secret key
        secretKey = pow(key, dh_private_key, P)

        # key generated might not be 256 bits. use a KDF to make it 256 bits.
        byteKey = secretKey.to_bytes((secretKey.bit_length() + 7)//8, byteorder='big')
        cipher = GCM(byteKey)

        print('---COMPLETED HANDSHAKE WITH SERVER', address, '---')
        print(servers)
        with dict_lock_servers:
            servers[address] = client_socket
        with dict_lock_ciphers:
            ciphers[address] = cipher
        if trusted:
            with dict_lock_initiated_widgets:
                if address in initiated_widgets:
                    initiated_widgets[address].config(bg='green')
        else:
            with dict_lock_untrusted_widgets:
                if address in untrusted_widgets:
                    untrusted_widgets[address].config(bg='green')
        print(servers)

        return (client_socket, cipher)

    except Exception as e:
        print("ERROR (create_sender) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (create_sender) for address " + address, e)

        client_socket.close()

        print('---CLOSING CONNECTION TO SERVER', address, '---')
        cleanup(address)

####################
## DATABASE
####################

# thread safety
file_lock_messages = threading.Lock() # for messages
file_lock_connections = threading.Lock() # for connections
file_lock_resources = threading.Lock() # for resources

# reads the connections.xml file
# <connections><connection><address>...</address> <key>...</key></connection>... </connections>
def read_connections():
    try:
        # thread safety
        with file_lock_connections:
            with open('connections.xml') as f:
                data = f.read()
        
        Bs_data = BeautifulSoup(data, "xml")
        b_connections = Bs_data.find_all("connection")
        
        data = {connection.find_all("address")[0].text: connection.find_all("key")[0].text for connection in b_connections}
    except Exception as e:
        print("ERROR:", e)
        data = dict()
       
    return data

# add an entry into connections.xml
def add_connection(address, key):
    try:
        with file_lock_connections:
            with open('connections.xml', 'r') as f:
                bs = BeautifulSoup(f, 'xml')

        # add data
        address_tag = bs.new_tag("address")
        address_tag.string = address

        key_tag = bs.new_tag("key")
        key_tag.string = key

        # add subtags to msg tag
        con_tag = bs.new_tag("connection")
        con_tag.append(address_tag)
        con_tag.append(key_tag)

        # add con tag to file
        connections = bs.find("connections")
        connections.append(con_tag)

        with file_lock_connections:
            with open('connections.xml', 'w') as f:
                f.write(str(bs))
    except Exception as e:
        print("ERROR (add_connection):", e)
        threadsafe_showinfo("Error (add_connection)!", e)

# remove an entry from connections.xml
def remove_connection(address):
    try:
        with file_lock_connections:
            with open('connections.xml', 'r') as f:
                bs = BeautifulSoup(f, 'xml')

        for item in bs.find_all('connection'):
            if item.find('address').string == address:
                item.decompose()

        with file_lock_connections:
            with open('connections.xml', 'w') as f:
                f.write(str(bs))
    except Exception as e:
        print("ERROR (remove_connection):", e)
        threadsafe_showinfo("Error (remove_connection)!", e)

# reads the messages.xml file
# <messages><message><text>...</text> <user>...</user> <channel>...</channel></message>... </messages>
def read_messages():
    try:
        # thread safety
        with file_lock_messages:
            with open('messages.xml') as f:
                data = f.read()

        Bs_data = BeautifulSoup(data, "xml")
        b_message = Bs_data.find_all("message")
     
        data = [{
                'text': msg.find('text').text,
                'user': msg.find('user').text,
                'channel': msg.find('channel').text
            } for msg in b_message]
           
        return data
    except Exception as e:
        print("ERROR (read_messages):", e)
        threadsafe_showinfo("Error (read_messages)!", e)
        return dict()

# check whether message exists
def message_exists(text, user, channel, time):
    try:
        # thread safety
        with file_lock_messages:
            with open('messages.xml') as f:
                data = f.read()

        Bs_data = BeautifulSoup(data, "xml")
        b_message = Bs_data.find_all("message")

        for msg in b_message:
            if msg.find('time').text.strip() == time.strip():
                if msg.find('user').text.strip() == user.strip():
                    if msg.find('text').text.strip() == text.strip():
                        if msg.find('channel').text.strip() == channel.strip():
                            return True
     
        return False
    except Exception as e:
        print("ERROR (message_exists):", e)
        threadsafe_showinfo("Error (message_exists)!", e)
        return False

# get hostname (username) from user's public key
# ssh-rsa ACTUAL_KEY user@hostname
def parse_user_key(user):
    try:
        username = user.split(' ')[-1]
        user_hostname = username.split('@')[-1].strip()
        return user_hostname
    except Exception as e:
        print("ERROR (parse_user_key):", e)
        threadsafe_showinfo("Error (parse_user_key)!", e)
        return 'ERROR'

# add an entry into messages.xml
def add_message(user, text, channel, time):
    try:
        with file_lock_messages:
            with open('messages.xml', 'r') as f:
                bs = BeautifulSoup(f, 'xml')

        # add data
        user_tag = bs.new_tag("user")
        user_tag.string = user

        text_tag = bs.new_tag("text")
        text_tag.string = text

        channel_tag = bs.new_tag("channel")
        channel_tag.string = channel

        time_tag = bs.new_tag("time")
        time_tag.string = time

        # add subtags to msg tag
        msg_tag = bs.new_tag("message")
        msg_tag.append(user_tag)
        msg_tag.append(text_tag)
        msg_tag.append(channel_tag)
        msg_tag.append(time_tag)

        # add msg tag to file
        messages = bs.find("messages")
        messages.append(msg_tag)

        ## TODO - add xml data encryption

        with file_lock_messages:
            with open('messages.xml', 'w') as f:
                f.write(str(bs))
    except Exception as e:
        print("ERROR (add_message):", e)
        threadsafe_showinfo("Error (add_message)!", e)

# remove all messages from messages.xml
def purge_messages():
    with file_lock_messages:
        with open('messages.xml', 'w') as f:
            f.write('<?xml version="1.0" encoding="utf-8"?><messages><</messages>')

    show_messages()

# reads the resources.xml file
# <resources><resource><type>...</type> <text>...</text> <label>...</label> <signature>...</signature></resource>... </resources>
def read_resources(resource_type=''):
    try:
        # thread safety
        with file_lock_resources:
            with open('resources.xml') as f:
                data = f.read()

        Bs_data = BeautifulSoup(data, "xml")
        b_labels = Bs_data.find_all("label")
     
        data = []

        data_by_label = dict()
        data_by_hash = dict()

        for label in b_labels:
            parent = label.parent

            if resource_type == '' or parent.find('type').text == resource_type:
                hashed = hashlib.sha256(label.text.encode() + parent.find('text').text.encode()).hexdigest()
                
                details = {
                    'text': parent.find('text').text,
                    'label': label.text,
                    'user': parent.find('user').text,
                    'signature': parent.find('signature').text,
                    'type': parent.find('type').text,
                    'hash': hashed,
                    'ip': self_ip_address,
                    'filename': parent.find('filename').text,
                    'filehash': parent.find('filehash').text,
                }
                
                if label.text in data_by_label.keys():
                    data_by_label[label.text].append(details)
                else:
                    data_by_label[label.text] = [details]

                if hashed in data_by_hash.keys():
                    data_by_hash[hashed].append(details)
                else:
                    data_by_hash[hashed] = [details]
                 
                data.append(details)
           
        return data, data_by_label, data_by_hash
    except Exception as e:
        print("ERROR (read_resources):", e)
        threadsafe_showinfo("Error (read_resources)!", e)
        return [], dict(), dict()

# add an entry into resources.xml
def add_resource(resource_type, text, label, user, filename='', filehash=None):
    try:
        with file_lock_resources:
            with open('resources.xml', 'r') as f:
                bs = BeautifulSoup(f, 'xml')

        # add data
        type_tag = bs.new_tag("type")
        type_tag.string = resource_type
        
        text_tag = bs.new_tag("text")
        text_tag.string = text

        label_tag = bs.new_tag("label")
        label_tag.string = label

        user_tag = bs.new_tag("user")
        user_tag.string = user

        filename_tag = bs.new_tag("filename")
        filename_tag.string = filename

        filehash_tag = bs.new_tag("filehash")
        if filehash == None:
            _, filehash = clean_pdf(filename)
        filehash_tag.string = filehash
        
        signature = sign(label.encode() + text.encode()).hex()
        signature_tag = bs.new_tag("signature")
        signature_tag.string = signature
        
        # add subtags to msg tag
        res_tag = bs.new_tag("resource")
        res_tag.append(type_tag)
        res_tag.append(text_tag)
        res_tag.append(label_tag)
        res_tag.append(user_tag)
        res_tag.append(signature_tag)
        res_tag.append(filename_tag)
        res_tag.append(filehash_tag)
        
        # add msg tag to file
        resources = bs.find("resources")
        resources.append(res_tag)

        ## TODO - add xml data encryption

        with file_lock_resources:
            with open('resources.xml', 'w') as f:
                f.write(str(bs))
    except Exception as e:
        print("ERROR (add_resource):", e)
        threadsafe_showinfo("Error (add_resource)!", e)

# refresh hashes
def refresh_resources():
    try:
        with file_lock_resources:
            with open('resources.xml', 'r') as f:
                bs = BeautifulSoup(f, 'xml')
        
        Bs_data = BeautifulSoup(bs, "xml")
        b_resources = Bs_data.find_all("resource")

        bs = BeautifulSoup("<resources></resources>", "xml")

        for resource in b_resourcess:
            print(resource)
            file = resource.find('filename').text
            print(file)
            _, hashed = clean_pdf(file)
            print(hashed)
            if hashed == '':
                resource.find('filename').string = ''
                resource.find('filehash').string = ''
            else:
                resource.find('filehash').string = hashed

            bs.append(resource)
            print("ADDED")

        with file_lock_resources:
            with open('resources.xml', 'w') as f:
                f.write(str(bs))
    except Exception as e:
        print("ERROR (refresh_resources):", e)
        threadsafe_showinfo("Error (refresh_resources)!", e)

####################
## MESSAGE HANDLING
####################

# show all messages in listbox
def show_messages(event=None):
    try:
        # database elements
        data = read_messages()

        # add database elements to gui
        messages_list.config(state=tk.NORMAL)
        messages_list.delete("1.0", tk.END)
        for each in data:
            # ensure message is in the correct channel
            if each['channel'] == channel.get():
                display = f"{parse_user_key(each['user'])}: {each['text']}\n"
                messages_list.insert(tk.END, display)
        messages_list.config(state=tk.DISABLED) 
    except Exception as e:
        print("ERROR (show_messages):", e)
        threadsafe_showinfo("Error (show_messages)!", e)

# update gui of messages
def update_listbox(display):
    try:
        messages_list.config(state=tk.NORMAL) 
        messages_list.insert(tk.END, display)
        messages_list.config(state=tk.DISABLED) 
    except Exception as e:
        print("ERROR (update_listbox):", e)
        threadsafe_showinfo("Error (update_listbox)!", e)

# add a message to the database from server directly
def send_message():
    try:
        text = send_text.get("1.0", "end-1c")
        if text.strip() == '': 
            threadsafe_showinfo("Error!", "Message empty!")
            return

        # add to database
        time = str(datetime.datetime.now())
        add_message(self_authentication_public_key_string, text, channel.get(), time)
        display = self_hostname + ': ' + text + '\n'

        print('---SENDING MESSAGE TO ALL SERVERS---')
        with dict_lock_servers:
            for address, client_socket in servers.items():
                print('ADDRESS:', address)

                # encrypt and sign message
                cipher = ciphers[address]

                msg = 'message'.encode() + ':::'.encode() + channel.get().encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(text) + ':::'.encode() + time.encode() + ':::'.encode() + sign(text.encode() + time.encode())
                sendall(client_socket, msg)
       
        update_listbox(display)

        threadsafe_showinfo("Message sent!", "Your message has been sent.")
    except Exception as e:
        print("ERROR (send_message):", e)
        threadsafe_showinfo("Error (send_message)!", e)

####################
## RESOURCES HANDLING
####################

# thread safety
resources_listbox_lock = threading.Lock()

list_resources_lock = threading.Lock()
all_resources = []

selected_listbox_item_lock = threading.Lock()
selected_listbox_item = None

# get information and add it to resources.xml
def create_resource():
    try:
        text = text_text.get("1.0", "end-1c")
        if text.strip() == '': 
            threadsafe_showinfo("Error!", "Text empty!")
            return
        
        label = label_entry.get()
        if label.strip() == '': 
            threadsafe_showinfo("Error!", "Label empty!")
            return

        add_resource('resource', text, label, self_authentication_public_key_string, filename_entry.get())
        reset_resources_listbox()

        threadsafe_showinfo("Resource added!", "Your resource has been created.")
        
    except Exception as e:
        print("ERROR (create_resource):", e)
        threadsafe_showinfo("Error (create_resource)!", e)

def create_comment():
    try:
        text = text_text.get("1.0", "end-1c")
        if text.strip() == '': 
            threadsafe_showinfo("Error!", "Text empty!")
            return
        
        label = label_entry.get()
        if label.strip() == '': 
            threadsafe_showinfo("Error!", "Label empty!")
            return

        add_resource('comment', text, label, self_authentication_public_key_string, filename_entry.get())
 
        reset_resources_listbox()

        threadsafe_showinfo("Comment added!", "Your comment has been created.")
        
    except Exception as e:
        print("ERROR (create_comment):", e)
        threadsafe_showinfo("Error (create_comment)!", e)

# query network for resource given label
def query_resource():
    try:
        label = label_entry.get()
        if label.strip() == '':
            hashed = hash_entry.get().strip()

            if hashed == '':
                threadsafe_showinfo("Error!", "Label empty!")
                return

            time = str(datetime.datetime.now())
            
            print('---SENDING QUERY TO ALL SERVERS---')
            with dict_lock_servers:
                for address, client_socket in servers.items():
                    print('ADDRESS:', address)

                    # encrypt and sign message
                    cipher = ciphers[address]
                    self_ip_address = client_socket.getsockname()[0]

                    msg = 'query_by_hash'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + sign(hashed.encode())
                    sendall(client_socket, msg)
       
            threadsafe_showinfo("Query sent!", "Your query has been sent.")
        else:
            time = str(datetime.datetime.now())
            
            print('---SENDING QUERY TO ALL SERVERS---')
            with dict_lock_servers:
                for address, client_socket in servers.items():
                    print('ADDRESS:', address)

                    # encrypt and sign message
                    cipher = ciphers[address]
                    self_ip_address = client_socket.getsockname()[0]

                    msg = 'query'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(label) + ':::'.encode() + time.encode() + ':::'.encode() + sign(label.encode() + time.encode())
                    sendall(client_socket, msg)
           
            threadsafe_showinfo("Query sent!", "Your query has been sent.")
    except Exception as e:
        print("ERROR (query_resource):", e)
        threadsafe_showinfo("Error (query_resource)!", e)

# query network for comments given the resource's hash
def query_comments():
    try:
        text = text_text.get("1.0", "end-1c")
        if text.strip() == '': 
            threadsafe_showinfo("Error!", "Text empty!")
            return
        
        label = label_entry.get()
        if label.strip() == '': 
            threadsafe_showinfo("Error!", "Label empty!")
            return
        
        with selected_listbox_item_lock:
            if selected_listbox_item == None:
                threadsafe_showinfo("None selected", "Please select a resource to find comments of")
                return

        with list_resources_lock:
            commenting_to = all_resources[selected_listbox_item]
            if commenting_to['label'] == label and commenting_to['text'] == text:
                hashed = hashlib.sha256(commenting_to['label'].encode() + commenting_to['text'].encode()).hexdigest()
            else:
                threadsafe_showinfo("Resource modified", "Please don't modify the selected resource")
                return
        
        time = str(datetime.datetime.now())
        
        print('---SENDING QUERY TO ALL SERVERS---')
        with dict_lock_servers:
            for address, client_socket in servers.items():
                print('ADDRESS:', address)

                # encrypt and sign message
                cipher = ciphers[address]
                self_ip_address = client_socket.getsockname()[0]

                msg = 'query_comments'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + sign(hashed.encode() + time.encode())
                sendall(client_socket, msg)
       
        threadsafe_showinfo("Query sent!", "Your query has been sent.")
    except Exception as e:
        print("ERROR (query_comments):", e)
        threadsafe_showinfo("Error (query_comments)!", e)

# select an item in the resources listbox
def select_resources_listbox():
    global selected_listbox_item

    try:
        selected_indices = resources_listbox.curselection()
        unselect_resources_listbox()
        
        if selected_indices:
            selected_indices = selected_indices[0]
            selected_value = resources_listbox.get(selected_indices)
            resources_listbox.itemconfig(selected_indices, bg="yellow", selectbackground="yellow")
            
            with selected_listbox_item_lock:
                selected_listbox_item = selected_indices
                
                hash_entry.config(state=tk.NORMAL)
                label_entry.config(state=tk.NORMAL)
                text_text.config(state=tk.NORMAL)
                filehash_entry.config(state=tk.NORMAL)
                
                hash_entry.delete(0, tk.END)
                label_entry.delete(0, tk.END)
                text_text.delete("1.0", tk.END)
                filename_entry.delete(0, tk.END)
                filehash_entry.delete(0, tk.END)

                with list_resources_lock:
                    selected = all_resources[selected_listbox_item]
                    label_entry.insert(0, selected['label'])
                    text_text.insert("1.0", selected['text'])
                    
                    filename_entry.insert(0, selected['filename'])
                    filehash_entry.insert(0, selected['filehash'])
                    filehash_entry.config(state="readonly")
                    
                    hash_entry.insert(0, hashlib.sha256(selected['label'].encode() + selected['text'].encode()).hexdigest())
                    hash_entry.config(state="readonly")
                    
    except Exception as e:
        print("ERROR (select_resources_listbox):", e)
        threadsafe_showinfo("Error (select_resources_listbox)!", e)

# unselect all items in the resources listbox
def unselect_resources_listbox():
    global selected_listbox_item
    
    resources_listbox.selection_clear(0, tk.END)
    
    hash_entry.config(state=tk.NORMAL)
    label_entry.config(state=tk.NORMAL)
    text_text.config(state=tk.NORMAL)
    filehash_entry.config(state=tk.NORMAL)
    
    hash_entry.delete(0, tk.END)
    label_entry.delete(0, tk.END)
    text_text.delete("1.0", tk.END)
    filename_entry.delete(0, tk.END)
    filehash_entry.delete(0, tk.END)
    
    with selected_listbox_item_lock:
        selected_listbox_item = None

    for i in range(resources_listbox.size()):
        resources_listbox.itemconfig(i, bg="white", selectbackground="grey")

# replace all items in resources listbox with database values
def reset_resources_listbox():
    global all_resources, selected_listbox_item
    
    data, _, _ = read_resources()

    with list_resources_lock:
        all_resources = list(data)

    with selected_listbox_item_lock:
        selected_listbox_item = None
    
    resources_listbox.delete(0, tk.END)

    for item in data:
        if item['type'] == 'comment':
            display = 'COMMENT: ' + item['label'] + ' (' + parse_user_key(item['user']) + ')'
        else:
            display = 'RESOURCE: ' + item['label'] + ' (' + parse_user_key(item['user']) + ')'
        resources_listbox.insert(tk.END, display)

# thread safe insertion to the listbox
def insert_to_resources_listbox(item):
    with resources_listbox_lock:
        resources_listbox.insert(tk.END, item)

def mirror_selected_resource():
    try:
        with selected_listbox_item_lock:
            with list_resources_lock:
                try:
                    assert selected_listbox_item != None
                    mirroring = all_resources[selected_listbox_item]
                except IndexError:
                    threadsafe_showinfo("Index Error!", "Could not find selected resource")
                    return
        
        # attached file
        if mirroring['filename'] != '':
            if filename_entry.get() == '':
                filename_entry.delete(0, tk.END)
                filename_entry.insert(0, mirroring['filename'])

            add_resource(mirroring['type'], mirroring['text'], mirroring['label'], mirroring['user'], filename_entry.get(), filehash=mirroring['filehash'])
            download_selected_resource()
        else:
            add_resource(mirroring['type'], mirroring['text'], mirroring['label'], mirroring['user'], filename_entry.get(), filehash=mirroring['filehash'])
        
        threadsafe_showinfo("Mirrored!", "The selected resource has been mirrored.")
        
    except Exception as e:
        print("ERROR (mirror_selected_resource):", e)
        threadsafe_showinfo("Error (mirror_selected_resource)!", e)

# download file associated with resource
def download_selected_resource():
    try:
        with selected_listbox_item_lock:
            with list_resources_lock:
                try:
                    assert selected_listbox_item != None
                    downloading = all_resources[selected_listbox_item]
                    downloading_hash = downloading['hash']
                    downloading_ip = downloading['ip']
                except IndexError:
                    threadsafe_showinfo("Index Error!", "Could not find selected resource")
                    return

        with dict_lock_servers:
            for address, client_socket in servers.items():
                if address == downloading_ip:  
                    # encrypt and sign message
                    cipher = ciphers[address]

                    msg = 'download'.encode() + ':::'.encode() + cipher.encrypt(downloading_hash)

                    with dict_lock_download_requests:
                        download_requests[address] = downloading_hash
                    
                    sendall(client_socket, msg)
   
                    threadsafe_showinfo("Query sent!", "Your query has been sent.")
                    return
        
    except Exception as e:
        print("ERROR (download_selected_resource):", e)
        threadsafe_showinfo("Error (download_selected_resource)!", e)

# lock text/label if hash is modified
def on_hash_modified(event):
    print("HASH MODIFIED")
    hashed = hash_entry.get()

    if hashed == '':
        label_entry.config(state=tk.NORMAL)
        text_text.config(state=tk.NORMAL) 
        text_text.config(bg='white')
    elif text_text.get("1.0", "end-1c") == '' and label_entry.get() == '':
        hash_entry.config(state=tk.NORMAL) 
        text_text.config(state=tk.DISABLED)
        text_text.config(bg='grey')
        label_entry.config(state=tk.DISABLED)

# lock hash if label/text is modified
def on_label_or_text_modified(event):
    print("LABEL/TEXT MODIFIED")
    
    text = text_text.get("1.0", "end-1c")
    label = label_entry.get()

    if text == '' and label == '':
        hash_entry.config(state=tk.NORMAL) 
        hash_entry.delete(0, tk.END)
    else:
        hashed = hashlib.sha256(label.encode() + text.encode()).hexdigest()
        hash_entry.config(state=tk.NORMAL) 
        hash_entry.delete(0, tk.END)
        hash_entry.insert(0, hashed)
        hash_entry.config(state="readonly") 

# recalculate the file hash based on filename (on user's local drive)
def recalculate_hash():
    filename = filename_entry.get()
    if filename.strip() == '': 
        threadsafe_showinfo("Error!", "Filename empty!")
        return

    file, hashed = clean_pdf(filename)

    filehash_entry.config(state=tk.NORMAL)
    filehash_entry.delete(0, tk.END)
    filehash_entry.insert(0, hashed)
    filehash_entry.config(state="readonly")

    if hashed == '':
        threadsafe_showinfo("File does not exist!", "Please correct the file name.")

# refreshes the resources db and the gui
def refresh_resources_gui():
    refresh_resources()
    reset_resources_listbox()

####################
## GUI
####################

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Create canvas and scrollbar
        canvas = tk.Canvas(self)
        scrollbar_v = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollbar_h = ttk.Scrollbar(self, orient="horizontal", command=canvas.xview)
        
        self.scrollable_frame = ttk.Frame(canvas)
        
        # Bind scroll region update to canvas resize
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Place window in canvas
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure canvas scrolling
        canvas.configure(yscrollcommand=scrollbar_v.set)
        canvas.configure(xscrollcommand=scrollbar_h.set)
        
        # Grid layout: Canvas in col 0, Scrollbar in col 1
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar_v.grid(row=0, column=1, sticky="ns")
        scrollbar_h.grid(row=1, column=0, sticky="ew")

# thread safe alerts
alert_q = queue.Queue()

def threadsafe_showinfo(title, message):
    alert_q.put(lambda: messagebox.showinfo(title, message))

def check_alert_queue():
    while not alert_q.empty():
        func = alert_q.get()
        func()
    root.after(100, check_alert_queue) # Check again in 100ms

# tk initialise
root = tk.Tk()
root.geometry('600x1000')
root.title('P2P LAN')
root.after(100, check_alert_queue)

# scrollable frame
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

frame = ScrollableFrame(root)
frame.grid(row=0, column=0, sticky="nsew")
master_frame = frame.scrollable_frame

# FRAME ONE - messages and chat
frame1 = tk.Frame(master_frame)
frame1.grid(padx=10, pady=10, sticky='nsew')

tk.Label(frame1, text='P2P LAN App', font=("Arial", 25)).grid(row=0, column=0, columnspan=3)

channel = tk.StringVar(root)
channel.set("general")

options = ["general", "spam", "casual"]

send_text = tk.Text(frame1, width=40, height=10)
send_text.grid(row=1, column=0, columnspan=2, sticky='ew')

send_but = tk.Button(frame1, text='Send', command=send_message)
send_but.grid(row=2, column=0, columnspan=1, sticky='ew')

channel_menu = tk.OptionMenu(frame1, channel, *options, command=show_messages)
channel_menu.grid(row=2, column=1, columnspan=1, sticky='ew')

messages_list = tk.Text(frame1, wrap='word', width=40, height=10)
messages_list.grid(row=1, column=2, columnspan=1, sticky='ew')

clear_but = tk.Button(frame1, text='Purge Chat', command=purge_messages)
clear_but.grid(row=2, column=2, columnspan=1, sticky='ew')

show_messages()

# FRAME TWO - RESOURCE QUERIES

frame2 = tk.Frame(master_frame)
frame2.grid(padx=10, pady=10, sticky='nsew')

tk.Label(frame2, text='Resources', font=("Arial", 25)).grid(row=0, column=0, columnspan=4)
tk.Label(frame2, text='To create a comment, copy the hash of the resource you want to comment to. Paste the hash into the "Label" entry.').grid(row=1, columnspan=4)

tk.Label(frame2, text='Hash:').grid(row=2, column=0, columnspan=1)
hash_entry = tk.Entry(frame2)
hash_entry.grid(row=2, column=1, columnspan=3, sticky='ew')
hash_entry.bind("<KeyRelease>", on_hash_modified)

tk.Label(frame2, text='Label:').grid(row=3, column=0, columnspan=1)
label_entry = tk.Entry(frame2)
label_entry.grid(row=3, column=1, columnspan=3, sticky='ew')
label_entry.bind("<KeyRelease>", on_label_or_text_modified)

tk.Label(frame2, text='Filename:').grid(row=4, column=0, columnspan=1)
filename_entry = tk.Entry(frame2)
filename_entry.grid(row=4, column=1, columnspan=3, sticky='ew')

tk.Label(frame2, text='File Hash:').grid(row=5, column=0, columnspan=1)
filehash_entry = tk.Entry(frame2, state="readonly")
filehash_entry.grid(row=5, column=1, columnspan=2, sticky='ew')

tk.Button(frame2, text='RECALCULATE HASH', command=recalculate_hash).grid(row=5, column=3, sticky='ew')

text_text = tk.Text(frame2, width=50, height=7)
text_text.grid(columnspan=6, sticky='ew')
text_text.bind("<KeyRelease>", on_label_or_text_modified)

tk.Button(frame2, text='ADD RESOURCE', command=create_resource).grid(row=7, column=0, sticky='ew')
tk.Button(frame2, text='ADD COMMENT', command=create_comment).grid(row=7, column=1, sticky='ew')
tk.Button(frame2, text='QUERY RESOURCES', command=query_resource).grid(row=7, column=2, sticky='ew')
tk.Button(frame2, text='QUERY COMMENTS', command=query_comments).grid(row=7, column=3, sticky='ew')

resources_listbox = tk.Listbox(frame2, selectmode=tk.SINGLE, width=50, height=7)
resources_listbox.grid(columnspan=4, sticky='ew')

tk.Button(frame2, text='SELECT', command=select_resources_listbox).grid(row=9, column=0, sticky='ew')
tk.Button(frame2, text='UNSELECT', command=unselect_resources_listbox).grid(row=9, column=1, sticky='ew')
tk.Button(frame2, text='REFRESH', command=refresh_resources_gui).grid(row=9, column=2, sticky='ew')
tk.Button(frame2, text='MIRROR', command=mirror_selected_resource).grid(row=9, column=3, sticky='ew')

reset_resources_listbox()

# FRAME THREE - CONNECTIONS MANAGER
frame3 = tk.Frame(master_frame)
frame3.grid(padx=10, pady=10, sticky='nsew')

tk.Label(frame3, text='Manage Connections', font=("Arial", 25)).grid(row=0, column=0, columnspan=2)

trusted = tk.Frame(frame3, height=1000, width=250)
trusted.grid(row=1, column=0, columnspan=1)
trusted.grid_propagate(0)

tk.Label(trusted, text='TRUSTED').grid(row=0, column=0)

spawn_but = tk.Button(trusted, text='Revive Connections', command=spawn_senders)
spawn_but.grid(row=1, column=0, columnspan=1)

trusted_list = tk.Frame(trusted, height=800, width=200)
trusted_list.grid(row=2, column=0, columnspan=1)
trusted_list.grid_propagate(0)

untrusted = tk.Frame(frame3, height=1000, width=250)
untrusted.grid(row=1, column=1, columnspan=1)
untrusted.grid_propagate(0)

tk.Label(untrusted, text='UNTRUSTED').grid(row=0, column=0)

untrusted_list = tk.Frame(untrusted, height=800, width=200)
untrusted_list.grid(row=1, column=0, columnspan=1)
untrusted_list.grid_propagate(0)

frame3.rowconfigure(0, weight=1)
frame3.rowconfigure(1, weight=1)

Thread(target=listen).start()
Thread(target=spawn_senders).start()

tk.mainloop()
