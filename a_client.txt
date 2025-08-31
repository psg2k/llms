import os
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt(data_bytes,key,mode):
    if mode=='ECB':
        cipher=AES.new(key,AES.MODE_ECB)
        padding_bytes=pad(data_bytes,AES.block_size)
        return cipher.encrypt(padding_bytes)
    elif mode=="CBC":
        cipher=AES.new(key,AES.MODE_CBC)
        padding_bytes=pad(data_bytes,AES.block_size)
        return cipher.iv + cipher.encrypt(padding_bytes)
    else :
        cipher= AES.new(key,AES.MODE_CFB)
        return cipher.iv + cipher.encrypt(data_bytes)

def start_client():
    host,port="127.0.0.1",9999
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        client.connect((host,port))
        key=client.recv(16)
        if not key:
            print("are you stupid:")
            return 
        data_type=input("enter text or file:")
        mode = input("Enter ECB,CBC,CFB mode:")
        original_data_bytes=None
        print("key is :",key.hex())
        if data_type=="text":
            message=input("Enter plain text message:")
            original_data_bytes=message.encode("utf-8")
            print("message is :",message)
        else:
            filepath=input("Enter filepath :")
            if not os.path.exists(filepath):
                print("file not exists")
                return 
            with open(filepath,'rb') as f:
                original_data_bytes=f.read()
        encrypted_data=encrypt(original_data_bytes,key,mode)
        print("cipher text is : ",encrypted_data.hex()[:80])
        header=f"{data_type:<10}{mode:<10}".encode('utf-8') #encode
        client.send(header) #header send
        client.send(encrypted_data)
            
    except ConnectionRefusedError:
        print("connection refused")
    except Exception as e:
        print("msg is:",e)
    finally:
        client.close()
start_client()