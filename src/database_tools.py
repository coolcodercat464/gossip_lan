from pdf_tools import get_pdf_data_clean
import hashlib
from bs4 import BeautifulSoup
from crypto_tools import sign

# thread safety
file_lock_messages = threading.Lock() # for messages
file_lock_connections = threading.Lock() # for connections
file_lock_resources = threading.Lock() # for resources

# reads the connections.xml file
# <connections><connection><address>...</address> <key>...</key></connection>... </connections>
# TODO - add trust levels
def read_connections():
    # thread safety
    with file_lock_connections:
        with open('connections.xml') as f:
            data = f.read()
    
    Bs_data = BeautifulSoup(data, "xml")
    b_connections = Bs_data.find_all("connection")
    
    data = {connection.find_all("address")[0].text: connection.find_all("key")[0].text for connection in b_connections}
    return data

# add an entry into connections.xml
def add_connection(address, key):
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

# remove an entry from connections.xml
def remove_connection(address):
    # get data
    with file_lock_connections:
        with open('connections.xml', 'r') as f:
            bs = BeautifulSoup(f, 'xml')

    # remove all entries from data
    for item in bs.find_all('connection'):
        if item.find('address').string == address:
            item.decompose()

    # overwrite data
    with file_lock_connections:
        with open('connections.xml', 'w') as f:
            f.write(str(bs))

# reads the messages.xml file
# <messages><message><text>...</text> <user>...</user> <channel>...</channel></message>... </messages>
def read_messages():
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

# check whether message exists
def message_exists(text, user, channel, time):
    # thread safety
    with file_lock_messages:
        with open('messages.xml') as f:
            data = f.read()

    Bs_data = BeautifulSoup(data, "xml")
    b_message = Bs_data.find_all("message")

    for msg in b_message:
        # compare arguments to current element until a message is found
        # TODO - do a more efficient search algorithm (date should be sorted!)
        if msg.find('time').text.strip() == time.strip():
            if msg.find('user').text.strip() == user.strip():
                if msg.find('text').text.strip() == text.strip():
                    if msg.find('channel').text.strip() == channel.strip():
                        return True
 
    return False

# get hostname (username) from user's public key
# ssh-rsa ACTUAL_KEY user@hostname
def parse_user_key(user):
    username = user.split(' ')[-1]
    user_hostname = username.split('@')[-1].strip()
    return user_hostname

# add an entry into messages.xml
def add_message(user, text, channel, time):
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
  
    with file_lock_messages:
        with open('messages.xml', 'w') as f:
            f.write(str(bs))

# remove all messages from messages.xml
def purge_messages():
    with file_lock_messages:
        with open('messages.xml', 'w') as f:
            f.write('<messages><</messages>')

    show_messages()

# reads the resources.xml file
# <resources><resource><type>...</type> <text>...</text> <label>...</label> <signature>...</signature> <filename>...</filename> <filehash>...</filehash> </resource>... </resources>
def read_resources(resource_type=''):
    # thread safety
    with file_lock_resources:
        with open('resources.xml') as f:
            data = f.read()

    Bs_data = BeautifulSoup(data, "xml")
    b_labels = Bs_data.find_all("label")

    data: list[dict[str, str]] = []

    data_by_label: dict[str, dict[str, str]] = dict()
    data_by_hash: dict[str, dict[str, str]] = dict()

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

            # add to data structures
            data_by_label.setdefault(label.text, []).append(details)
            data_by_hash.setdefault(hashed, []).append(details)            
            data.append(details)
       
    return data, data_by_label, data_by_hash

# add an entry into resources.xml
def add_resource(resource_type, text, label, user, private_key, filename='', filehash=None):
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
        _, filehash = get_pdf_data_clean(filename)
    filehash_tag.string = filehash
    
    signature = sign(label.encode() + text.encode() + filehash.encode(), private_key).hex()
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

    with file_lock_resources:
        with open('resources.xml', 'w') as f:
            f.write(str(bs))

# refresh hashes
def refresh_resources():
    print("REFRESH")
    with file_lock_resources:
        with open('resources.xml', 'r') as f:
            bs = BeautifulSoup(f, 'xml')

    b_resources = bs.find_all("resource")

    bs = BeautifulSoup("<resources></resources>", "xml")

    for resource in b_resources:
        file = resource.find('filename').text
        _, hashed = get_pdf_data_clean(file)
        # do nothing if there is no attached file
        if hashed == '':
            resource.find('filename').string = ''
            resource.find('filehash').string = ''
        # otherwise, refresh the hash
        else:
            resource.find('filehash').string = hashed

        bs.find("resources").append(resource)

    with file_lock_resources:
        with open('resources.xml', 'w') as f:
            f.write(str(bs))
