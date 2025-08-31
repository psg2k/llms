import os
import socket
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes 

def recvall(client,n):
    data=b""
    while len(data)<n:
        packet=client.recv(n-len(data))
        if not packet:
            return None
        data+=packet
    return data 
        
def decrypt(encrypted_data,key,mode):
    if mode=='ECB':
        cipher=AES.new(key,AES.MODE_ECB)
        decrypted_pad=cipher.decrypt(encrypted_data)
        return unpad(decrypted_pad,AES.block_size)
    elif mode=='CBC':
        iv=encrypted_data[:AES.block_size]
        cipher=AES.new(key,AES.MODE_CBC,iv=iv) # add iv
        encrypted_data=encrypted_data[AES.block_size:]
        decrypted_pad=cipher.decrypt(encrypted_data)
        return unpad(decrypted_pad,AES.block_size)
    else:
        iv=encrypted_data[:AES.block_size]
        encrypted_data=encrypted_data[AES.block_size:]
        cipher=AES.new(key,AES.MODE_CFB,iv=iv)
        return cipher.decrypt(encrypted_data)

def start_server():
    host,port="127.0.0.1",9999
    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((host,port))
    server.listen(1)
    client,addr=server.accept()
    print("the address is :",addr)
    try:    
        key=get_random_bytes(16)
        client.send(key)
        print("key:",key.hex())
        header=recvall(client,20)
        data_type=header[:10].decode('utf-8').strip() #decoder and then strip
        mode=header[10:].decode('utf-8').strip()
        print(f"data type:{data_type},mode:{mode}")
        encrypted_data=client.recv(4096)
        print("cipher text is ",encrypted_data.hex()[:80])
        decrypted_text=decrypt(encrypted_data,key,mode)
        
        if decrypted_text:
            print("dec success") 
            message=decrypted_text.decode('utf-8') # decode
            print("message is :",message)
        
    except Exception as e:
        print("error is:",e)
    finally : 
        client.close()
        server.close()

start_server()