import socket

# send message + byte size
def sendall(this_socket, content, dict_lock_socket_locks):
    # use threading locks to ensure that the socket isn't being used to send multiple things at the same time
    address = this_socket.getpeername()
    with dict_lock_socket_locks:
        this_socket_lock = all_socket_locks[address]
    
    with this_socket_lock:
        print("---Sending Information---")

        # add the byte size to the start of the message
        byte_size = str(len(content))
        msg = byte_size + ' '

        this_socket.sendall(msg.encode() + content)

# receive all (no matter byte size)
def recvall(this_socket, dict_lock_socket_locks, chunk_size=1024):
    # use threading locks to ensure that the socket isn't being used to receive multiple things at the same time
    address = this_socket.getpeername()
    with dict_lock_socket_locks:
        this_socket_lock = all_socket_locks[address]

    with this_socket_lock:
        print("---Waiting for Message---")

        # receive the first chunk
        first_chunk = this_socket.recv(chunk_size)
      
        # connection terminated
        if not first_chunk:
            return False

        # get the message size
        space_enc = ' '.encode()
        splitted = first_chunk.split(space_enc)
        byte_size = int(splitted[0].decode())
        everything_else = space_enc.join(splitted[1:])

        # the entire message has been received
        if len(everything_else) == int(byte_size):
            return everything_else

        # still more to receive
        else:
            # decrease the counter
            all_chunks = everything_else
            byte_size -= len(everything_else)

            # keep receiving messages until counter hits zero
            while byte_size > 0:
                next_chunk = this_socket.recv(chunk_size)
              
                # connection terminated
                if not next_chunk:
                    return False
                
                all_chunks += next_chunk
                byte_size -= len(next_chunk)

            return all_chunks
