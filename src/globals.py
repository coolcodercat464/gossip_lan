# list of all server sockets
list_lock_all_servers = threading.Lock()
dict_lock_servers = threading.Lock()
dict_lock_socket_locks = threading.Lock()
dict_lock_ciphers = threading.Lock()

dict_lock_untrusted_keys = threading.Lock()
dict_lock_trusted_keys = threading.Lock()

import threading

list_lock_all_requests = threading.Lock()
list_lock_all_requests_comments = threading.Lock()

dict_lock_initiated_widgets = threading.Lock()
dict_lock_untrusted_widgets = threading.Lock()

dict_lock_download_requests = threading.Lock()
dict_lock_resources_by_label = threading.Lock()
dict_lock_resources_by_hash = threading.Lock()
dict_lock_comments_by_hash = threading.Lock()

all_servers = [] # list of addresses
servers = dict() # address -> socket
all_socket_locks = dict() # address -> socket lock (threading.Lock())
ciphers = dict() # address -> cipher object

untrusted_keys = dict() # address -> public key
trusted_keys = dict() # address -> public key

all_requests = [] # list of requests: tuple(sender_public_key, hashed, time)
all_requests_comments = [] # lists of requests for comments: tuple(sender_public_key, hashed, time)

initiated_widgets = dict() # address -> tkinter widget
untrusted_widgets = dict() # address -> tkinter widget

download_requests = dict() # address -> downloaded resource hash

# from database_tools
resources_by_label = dict() # data_by_label
resources_by_hash = dict() # data_by_hash (resource only)
comments_by_hash = dict() # data_by_hash (comments only)
