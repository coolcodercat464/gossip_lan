import threading

# thread safe object (global variable, sharable state)
class SafeSharedState:
    def __init__(self):
        self.value = value
        self.tlock = threading.Lock()

    def get(self):
        with self.tlock:
            return self.value

    def get_no_lock(self):
        return self.value

    def set(self, value):
        with self.tlock:
            self.value = value
    
    def lock(self):
        return self.tlock

# thread safe list (global variable, sharable state)
class SafeList(SafeSharedState):
    def __init__(self, value=[]):
        super().__init__(value)

    def append(self, item):
        with self.tlock:
            self.value.append(item)

# thread safe dict (global variable, sharable state)
class SafeDict(SafeSharedState):
    def __init__(self, value=dict()):
        super().__init__(value)

    def set(self, key, value):
        with self.tlock:
            self.value[key] = value

all_servers = SafeList() # list of addresses
servers = SafeDict() # address -> socket
all_socket_locks = SafeDict() # address -> socket lock (threading.Lock())
ciphers = SafeDict() # address -> cipher object

untrusted_keys = SafeDict() # address -> public key
trusted_keys = SafeDict() # address -> public key

all_requests = SafeList() # list of requests: tuple(sender_public_key, hashed, time)
all_requests_comments = SafeList() # lists of requests for comments: tuple(sender_public_key, hashed, time)

initiated_widgets = SafeDict() # address -> tkinter widget
untrusted_widgets = SafeDict() # address -> tkinter widget

download_requests = SafeDict() # address -> downloaded resource hash

# from database_tools
resources_by_label = SafeDict() # data_by_label
resources_by_hash = SafeDict() # data_by_hash (resource only)
comments_by_hash = SafeDict() # data_by_hash (comments only)
