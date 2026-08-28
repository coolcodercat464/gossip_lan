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

# custom modules
from pdf_tools import get_pdf_data_clean
from crypto_tools import GCM, verify
from socket_tools import get_local_ip
from database_tools import *
from globals import *

import socket_tools
import crypto_tools
import database_tools

# misc
import datetime
import builtins
import os
import json

# queues
from collections import deque
import queue # more thread safe apparently

# gui
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

####################
## AUTHENTICATION
####################

# load local ssh public and private keys
# generated with 'ssh-keygen -t ed25519'
with open('key.pub', 'rb') as key_file:
    public_key_bytes = key_file.read()

# get details about yourself
self_authentication_public_key_string = public_key_bytes.decode()
self_authentication_public_key = serialization.load_ssh_public_key(public_key_bytes)
self_hostname = socket.gethostname()
self_ip_address = get_local_ip()

# launch app
print("WELCOME TO P2P LAN")
print("Your username is:", self_hostname)
print("You can change this by changing your hostname.")
print("Your IP address is:", self_ip_address)
print("Your public key is:", self_authentication_public_key_string)

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

####################
## FUNCTIONS
####################

# thread-safe print
print_lock = threading.Lock()
original_print = builtins.print
def custom_print(*args):
    with print_lock: original_print(*args)
builtins.print = custom_print

# sendall/recvall functions with dict_lock_socket_locks and all_socket_locks
def sendall(this_socket, content):
    return socket_tools.sendall(this_socket, content, all_socket_locks.get())

def recvall(this_socket, chunksize=1024):
    return socket_tools.recvall(this_socket, all_socket_locks.get(), chunksize)

# signature function
def sign(message): 
    return crypto_tools.sign(message, self_authentication_private_key)

# add resource function
def add_resource(resource_type, text, label, user, filename='', filehash=None):
    return database_tools.add_resource(resource_type, text, label, user, self_authentication_private_key, filename='', filehash=None)

####################
## LISTENER
####################

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
                print(content)
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
        trust_this_connection = False
        
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
            trust_this_connection = True
            add_sender(address, client_authentication_public_key, True)
            trusted_keys.set_pair(address, client_authentication_public_key)
        else:
            # untrusted
            add_sender(address, client_authentication_public_key, False)
            untrusted_keys.set_pair(address, client_authentication_public_key)

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
                            for a, client_socket in servers.get().items():
                                print('ADDRESS:', a)
                    
                                # encrypt and sign message
                                cipher2 = ciphers.get()[a]
                    
                                msg = 'message'.encode() + ':::'.encode() + channel.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(text) + ':::'.encode() + time.encode() + ':::'.encode() + signature
                                sendall(client_socket, msg)

                    else:
                        raise Exception("Signature invalid")

                # resources query
                elif command == b'query':
                    # msg = 'query'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(label) + ':::'.encode() + time.encode() + ':::'.encode() + sign(label.encode() + time.encode())

                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])
                    label = cipher.decrypt(content.split(b':::')[2])
                    time = content.split(b':::')[3].decode()
                    signature = content.split(b':::')[4]
                    trust_chain = content.split(b':::')[5:]

                    if verify(sender_public_key, signature, label.encode() + time.encode()):
                        # prevent duplicates from blowing up
                        if not all_requests.present((sender_public_key, label, time)):
                            all_requests.append((sender_public_key, label, time))

                            # check if you have resource
                            data_by_label = dict(resources_by_label.get())
                            resources_found = []
                            for l in data_by_label.keys():
                                if label in l:
                                    for r in data_by_label[l]:
                                        resources_found.append(r)

                            # if resources are found...
                            if len(resources_found) > 0:
                                resources_string = json.dumps(resources_found)

                                t = threading.Thread(target=add_sender_for_resource, args=('response', sender_ip_address, sender_public_key, False, resources_string, trust_chain))
                                t.start()

                            # gossip protocol
                            print('---SENDING MESSAGE TO ALL SERVERS---')
                            for a, client_socket in servers.get().items():
                                # prevent it from mirroring back to the sender
                                if a != address:
                                    print('ADDRESS:', a)

                                    trust = ''

                                    # client is untrusted
                                    if a in untrusted_keys.get().keys():
                                        trust = 'UNTRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + trusted_keys.get()[a].encode()
                                        trust_sig = sign(trust)
                                        trust += '   '.encode()
                                        trust += trust_sig

                                    # client is trusted
                                    if a in trusted_keys.get().keys():
                                        trust = 'TRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + trusted_keys.get()[a].encode()
                                        trust_sig = sign(trust)
                                        trust += '   '.encode()
                                        trust += trust_sig

                                    # add to the trust chain
                                    if trust != '':
                                        new_trust_chain = trust_chain + [trust]
                                        new_trust_chain = b':::'.join(new_trust_chain)
                        
                                        # encrypt and sign message
                                        cipher2 = ciphers.get()[a]

                                        msg = 'query'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(label) + ':::'.encode() + time.encode() + ':::'.encode() + signature + ':::'.encode() + new_trust_chain
                                        sendall(client_socket, msg)
                    else:
                        raise Exception("Signature invalid")

                # resources query by hash
                elif command == b'query_by_hash':
                    # msg = 'query_by_hash'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + sign(hashed.encode())

                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])
                    hashed = cipher.decrypt(content.split(b':::')[2])
                    time = content.split(b':::')[3].decode()    
                    signature = content.split(b':::')[4]
                    trust_chain = content.split(b':::')[5:]

                    if verify(sender_public_key, signature, hashed.encode()):
                        # prevent duplicates from blowing up
                        if not all_requests.present((sender_public_key, label, time)):
                            all_requests.append((sender_public_key, hashed, time))

                            # check if you have resource
                            data_by_hash = dict(resources_by_hash.get())

                            if hashed in data_by_hash.keys():
                                resources_found = data_by_hash[hashed]
                                resources_string = json.dumps(resources_found)

                                t = threading.Thread(target=add_sender_for_resource, args=('response', sender_ip_address, sender_public_key, False, resources_string, trust_chain))
                                t.start()

                            # gossip protocol
                            print('---SENDING MESSAGE TO ALL SERVERS---')
                            for a, client_socket in servers.get().items():
                                if a != address:
                                    print('ADDRESS:', a)

                                    trust = ''
                                    
                                    if a in untrusted_keys.get().keys():
                                        trust = 'UNTRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + trusted_keys.get()[a].encode()
                                        trust_sig = sign(trust)
                                        trust += '   '.encode()
                                        trust += trust_sig

                                    if a in trusted_keys.get().keys():
                                        trust = 'TRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + trusted_keys.get()[a].encode()
                                        trust_sig = sign(trust)
                                        trust += '   '.encode()
                                        trust += trust_sig

                                    if trust != '':
                                        new_trust_chain = trust_chain + [trust]
                                        new_trust_chain = b':::'.join(new_trust_chain)
                        
                                        # encrypt and sign message
                                        cipher2 = ciphers.get()[a]

                                        msg = 'query_by_hash'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + signature + ':::'.encode() + new_trust_chain
                                        sendall(client_socket, msg)
                    else:
                        raise Exception("Signature invalid")
                        
                # comments query
                elif command == b'query_comments':
                    sender_public_key = cipher.decrypt(content.split(b':::')[0])
                    sender_ip_address = cipher.decrypt(content.split(b':::')[1])
                    resource_hash = cipher.decrypt(content.split(b':::')[2])
                    time = content.split(b':::')[3].decode()
                    signature = content.split(b':::')[4]
                    trust_chain = content.split(b':::')[5:]

                    if verify(sender_public_key, signature, resource_hash.encode() + time.encode()):
                        # prevent duplicates from blowing up
                        if not all_requests.present((sender_public_key, label, time)):
                            all_requests_comments.append((sender_public_key, resource_hash, time))

                            # check if you have resource
                            with dict_lock_comments_by_hash:
                                data_by_hash = dict(comments_by_hash)

                            if resource_hash in data_by_hash.keys():
                                comments_string = json.dumps(data_by_hash[resource_hash])

                                t = threading.Thread(target=add_sender_for_resource, args=('response_comment', sender_ip_address, sender_public_key, False, comments_string, trust_chain))
                                t.start()

                            print('---SENDING MESSAGE TO ALL SERVERS---')
                            with dict_lock_servers:
                                for a, client_socket in servers.items():
                                    if a != address:
                                        print('ADDRESS:', a)

                                        trust = ''
                                        if a in untrusted_keys.get().keys():
                                            trust = 'UNTRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + untrusted_keys.get()[a].encode()
                                            trust_sig = sign(trust)
                                            trust += '   '.encode()
                                            trust += trust_sig

                                        if a in trusted_keys.get().keys():
                                            trust = 'TRUSTED   '.encode() + str(datetime.datetime.now()).encode() + '   '.encode() + self_authentication_public_key_string.encode() + '   '.encode() + trusted_keys.get()[a].encode()
                                            trust_sig = sign(trust)
                                            trust += '   '.encode()
                                            trust += trust_sig

                                        if trust != '':
                                            new_trust_chain = trust_chain + [trust]
                                            new_trust_chain = b':::'.join(new_trust_chain)
                            
                                            # encrypt and sign message
                                            cipher2 = ciphers.get()[a]

                                            msg = 'query_comments'.encode() + ':::'.encode() + cipher2.encrypt(sender_public_key) + ':::'.encode() + cipher2.encrypt(sender_ip_address) + ':::'.encode() + cipher2.encrypt(resource_hash) + ':::'.encode() + time.encode() + ':::'.encode() + signature + ':::'.encode() + new_trust_chain
                                            sendall(client_socket, msg)
                    else:
                        raise Exception("Signature invalid")
                        
                # get response from query
                elif command == b'response':
                    # msg = 'response'.encode() + ':::'.encode() + cipher.encrypt(resources_string)
                    resources_encoded = content.split(b':::')[0]
                    trust_chain = content.split(b':::')[1:]
                    resources_string = cipher.decrypt(resources_encoded)
                    resources_obj = json.loads(resources_string)

                    # verify trust chain
                    if trust_this_connection:
                        transitive_trust_valid = "TRUSTED"
                        transitive_trust_hops = 1
                    else:
                        transitive_trust_valid = "UNTRUSTED"
                        transitive_trust_hops = 1

                        # follow the transitive trust chain
                        if len(trust_chain[0]) > 1:
                            transitive_trust_valid = "TRUSTED"
                            this_key = None

                            # verify every link
                            for link in trust_chain:
                                transitive_trust_hops += 1
                                trust, time, current_key, next_key, signature = link.split(b'   ')
                                string = b'   '.join([trust, time, current_key, next_key])
                                if this_key != None and this_key != current_key:
                                    raise Exception("Invalid trust chain")
                                else:
                                    this_key = next_key
                                
                                if verify(current_key.decode(), signature, string):
                                    if trust != b'TRUSTED': transitive_trust_valid = "UNTRUSTED"
                                else:
                                    raise Exception("Signature invalid (invalid trust chain)")

                    for resource in resources_obj:
                        resource_pub_key = resource['user'].strip()
                        signature = bytes.fromhex(resource['signature'].strip())
                        if verify(resource_pub_key, signature, resource['label'].encode() + resource['text'].encode() + resource['filehash'].encode()):
                            all_resources.append(resource)
                            item = 'QUERY RESPONSE (' + transitive_trust_valid + ' over ' + str(transitive_trust_hops) + ' hop FROM ' + parse_user_key(client_authentication_public_key) + '): ' + resource['label'] + ' (' + parse_user_key(resource['user']) + ')'
                            insert_to_resources_listbox(item)
                        else:
                            raise Exception("Signature invalid")

                # get response from comment query
                elif command == b'response_comment':
                    comments_encoded = content.split(b':::')[0]
                    trust_chain = content.split(b':::')[1:]
                    comments_string = cipher.decrypt(comments_encoded)
                    comments_obj = json.loads(comments_string)

                    # verify trust chain
                    if trust_this_connection:
                        transitive_trust_valid = "TRUSTED"
                        transitive_trust_hops = 1
                    else:
                        transitive_trust_valid = "UNTRUSTED"
                        transitive_trust_hops = 1
                        if len(trust_chain[0]) > 1:
                            transitive_trust_valid = "TRUSTED"
                            this_key = None
                            for link in trust_chain:
                                transitive_trust_hops += 1
                                trust, time, current_key, next_key, signature = link.split(b'   ')
                                string = b'   '.join([trust, time, current_key, next_key])
                                if this_key != None and this_key != current_key:
                                    raise Exception("Invalid trust chain")
                                else:
                                    this_key = next_key
                                
                                if verify(current_key.decode(), signature, string):
                                    if trust != b'TRUSTED': transitive_trust_valid = "UNTRUSTED"
                                else:
                                    raise Exception("Signature invalid (invalid trust chain)")

                    for comment in comments_obj:
                        comment_pub_key = comment['user']
                        signature = bytes.fromhex(comment['signature'])
                        if verify(comment_pub_key, signature, comment['label'].encode() + comment['text'].encode() + comment['filehash'].encode()):
                            all_resources.append(comment)
                            item = 'COMMENT QUERY RESPONSE (' + transitive_trust_valid + ' over ' + str(transitive_trust_hops) + ' hop FROM ' + parse_user_key(client_authentication_public_key) + '): ' + comment['label'] + ' (' + parse_user_key(comment['user']) + ')'
                            insert_to_resources_listbox(item)
                        else:
                            raise Exception("Signature invalid")

                # request to send a file over
                elif command == b'download':
                    # msg = 'download'.encode() + ':::'.encode() + cipher.encrypt(hashed)

                    resource_hash = cipher.decrypt(content.split(b':::')[0])
                    print(resource_hash)

                    # check if you have resource
                    data_by_hash = dict(resources_by_hash.get())

                    if resource_hash in data_by_hash.keys():
                        resource = data_by_hash[resource_hash][0]
                        
                        path = resource['filename']
                        file, hashed = get_pdf_data_clean(path)

                        # ensure file exists
                        if hashed != '':
                            # find the client and send it
                            for a, client_socket in servers.get().items():
                                if a == communication_socket.getpeername()[0]:
                                    cipher2 = ciphers.get()[a]
                                    sendall(client_socket, 'download_response:::'.encode() + file)

                # get response from download request
                elif command == b'download_response':
                    file = content
                    hashed = hashlib.sha256(content).hexdigest()

                    hashed = download_requests.get()[address]
                    download_requests.del(address)

                    path = filename_entry.get()
                    
                    with open(path, "wb") as f:
                        f.write(file)

                    _, hashed = get_pdf_data_clean(path)

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

            all_socket_locks.set_pair(address, threading.Lock())

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
    server_exists = servers.present(address)
    if server_exists:
        server_exists.close()
        servers.del(address)
    if all_servers.present(address):
        all_servers.remove(address)
    if ciphers.present(address):
        ciphers.del(address)

    widget = untrusted_widgets.present(address)
    if widget:
        widget.config(bg='red')

    widget = initiated_widgets.present(address)
    if widget:
        widget.config(bg='red')

# remove widget from tkinter display
def destroy_widget(address):
    try:
        if not all_servers.present(address):
            widget = untrusted_widgets.present(address)
            if widget:
                widget.master.destroy()
                untrusted_widgets.del(address)
        
            widget = initiated_widgets.present(address)
            if widget:
                widget.master.destroy()
                initiated_widgets.del(address)

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
            key = untrusted_keys.present(address)
            if key:
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
        text = address + ' (' + parse_user_key(key) + ')'
        
        child = tk.Frame(trusted_list)
        child.grid(padx=10, pady=10)
        
        widget = tk.Label(child, text=text, wraplength=100, bg='yellow')
        widget.grid(row=0, column=0, rowspan=2)
        
        initiated_widgets.value[address] = widget
    else:
        text = address + ' (' + parse_user_key(key) + ')'
        
        child = tk.Frame(untrusted_list)
        child.grid(padx=10, pady=10)
        
        widget = tk.Label(child, text=text, wraplength=100, bg='yellow')
        widget.grid(row=0, column=0, rowspan=2)
        
        untrusted_widgets.value[address] = widget
    
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
        continue_logic = not all_servers.present(address)

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
def add_sender_for_resource(response_type, address, key, trusted, resources_string, trust_chain):
    try:
        print('ADDING SENDER (FOR RESOURCE) TO ADDRESS:', address)
        
        continue_logic = False
        continue_logic = not all_servers.present(address)

        if continue_logic:
            destroy_widget(address)
            all_servers.append(address)
            widget = add_sender_gui(address, key, trusted)

            # create the actual socket
            client_socket, cipher = create_sender(address, key, widget, trusted)

            msg = response_type.encode() + ':::'.encode() + cipher.encrypt(resources_string) + ':::'.encode() + b':::'.join(trust_chain)
            sendall(client_socket, msg)
        else:
            exists = False
            client_socket = servers.present(address)
            if client_socket:
                cipher = ciphers.present(address)
                if cipher:
                    exists = True

            if exists:
                msg = response_type.encode() + ':::'.encode() + cipher.encrypt(resources_string) + ':::'.encode() + b':::'.join(trust_chain)
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
        
        all_socket_locks.value[server] = threading.Lock()

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

        servers.value[address] = client_socket
        ciphers.value[address] = cipher
        if trusted:
            widget = initiated_widgets.present(address)
            if widget:
                widget.config(bg='green')
        else:
            widget = untrusted_widgets.present(address)
            if widget:
                widget.config(bg='green')

        print(servers)

        return (client_socket, cipher)

    except Exception as e:
        print("ERROR (create_sender) FOR ADDRESS", address, ":", e)
        threadsafe_showinfo("Error (create_sender) for address " + address, e)

        client_socket.close()

        print('---CLOSING CONNECTION TO SERVER', address, '---')
        cleanup(address)

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
        
        for address, client_socket in servers.get().items():
            print('ADDRESS:', address)

            # encrypt and sign message
            cipher = ciphers.get()[address]

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
            for address, client_socket in servers.get().items():
                print('ADDRESS:', address)

                # encrypt and sign message
                cipher = ciphers.get()[address]
                self_ip_address = client_socket.getsockname()[0]

                msg = 'query_by_hash'.encode() + ':::'.encode() + cipher.encrypt(self_authentication_public_key_string) + ':::'.encode() + cipher.encrypt(self_ip_address) + ':::'.encode() + cipher.encrypt(hashed) + ':::'.encode() + time.encode() + ':::'.encode() + sign(hashed.encode())
                sendall(client_socket, msg)
       
            threadsafe_showinfo("Query sent!", "Your query has been sent.")
        else:
            time = str(datetime.datetime.now())
            
            print('---SENDING QUERY TO ALL SERVERS---')
            for address, client_socket in servers.items():
                print('ADDRESS:', address)

                # encrypt and sign message
                cipher = ciphers.get()[address]
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

        if selected_listbox_item.get() == None:
            threadsafe_showinfo("None selected", "Please select a resource to find comments of")
            return

        commenting_to = all_resources.get()[selected_listbox_item]
        if commenting_to['label'] == label and commenting_to['text'] == text:
            hashed = hashlib.sha256(commenting_to['label'].encode() + commenting_to['text'].encode()).hexdigest()
        else:
            threadsafe_showinfo("Resource modified", "Please don't modify the selected resource")
            return
        
        time = str(datetime.datetime.now())
        
        print('---SENDING QUERY TO ALL SERVERS---')
        for address, client_socket in servers.get().items():
            print('ADDRESS:', address)

            # encrypt and sign message
            cipher = ciphers.get()[address]
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

                selected = all_resources.get()[selected_listbox_item]
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
    
    selected_listbox_item.set(None)

    for i in range(resources_listbox.size()):
        resources_listbox.itemconfig(i, bg="white", selectbackground="grey")

# replace all items in resources listbox with database values
def reset_resources_listbox():
    global all_resources, selected_listbox_item, resources_by_label, resources_by_hash, comments_by_hash
    
    data, data_by_labels, data_by_hashes = read_resources()
    _, comment_hash, _ = read_resources(resource_type='comment')

    resources_by_label.set(dict(data_by_labels))
    resources_by_hash.set(dict(data_by_hashes))
    comments_by_hash.set(dict(comment_hash))
    all_resources.set(list(data))
    selected_listbox_item.set(None)
    
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
        try:
            assert selected_listbox_item.get() != None
            mirroring = all_resources.get()[selected_listbox_item]
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
        try:
            assert selected_listbox_item.get() != None
            downloading = all_resources.get()[selected_listbox_item]
            downloading_hash = downloading['hash']
            downloading_ip = downloading['ip']
        except IndexError:
            threadsafe_showinfo("Index Error!", "Could not find selected resource")
            return

        for address, client_socket in servers.get().items():
            if address == downloading_ip:  
                # encrypt and sign message
                cipher = ciphers.get()[address]

                msg = 'download'.encode() + ':::'.encode() + cipher.encrypt(downloading_hash)
                download_requests.set_pair(address, downloading_hash)
                
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

    file, hashed = get_pdf_data_clean(filename)

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

tk.Label(frame2, text='Filename (Save to):').grid(row=4, column=0, columnspan=1)
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
