import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures
import base64

# Constants
BLOCK_SIZE = 16
BLOCK_MULTIPLIER = 100
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.1234567890"
maxWorker = 10

# Helper Functions
def generateKey(length, key):
    retKey = str()
    for i in range(length):
        retKey += key[i % len(key)]
    return retKey

def vencrypt(msg, key):
    key = generateKey(len(msg), key)
    ciphertext = "E"
    for index, char in enumerate(msg):
        ciphertext += ALPHABET[(ALPHABET.find(key[index]) + ALPHABET.find(char)) % len(ALPHABET)]
    return ciphertext

def vdecrypt(ciphertext, key):
    key = generateKey(len(ciphertext), key)
    msg = str()
    ciphertext = ciphertext[1:]
    for index, char in enumerate(ciphertext):
        msg += ALPHABET[(ALPHABET.find(char) - ALPHABET.find(key[index])) % len(ALPHABET)]
    return msg

def pad(msg, BLOCK_SIZE, PAD):
    return msg + PAD * ((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE)

def encrypt(key, msg):
    PAD = b'\0'
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
    return result

def decrypt(key, msg):
    PAD = b'\0'
    decipher = AES.new(key, AES.MODE_ECB)
    pt = decipher.decrypt(msg)
    for i in range(len(pt)-1, -1, -1):
        if pt[i] == PAD:
            pt = pt[:i]
        else:
            break
    return pt

def encryptFile(file_content, file_name, password):
    try:
        logging.info("Started encoding: " + file_name)
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        encrypted_file_name = vencrypt(file_name, password) + ".enc"
        encrypted_content = b""
        start = 0
        while start < len(file_content):
            chunk = file_content[start:start + BLOCK_SIZE * BLOCK_MULTIPLIER]
            encrypted_content += encrypt(hkey, chunk)
            start += BLOCK_SIZE * BLOCK_MULTIPLIER
        logging.info("Encoded " + file_name)
        return encrypted_file_name, encrypted_content
    except Exception as e:
        return e

def decryptFile(file_content, file_name, password):
    logging.info("Started decoding: " + file_name)
    try:
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        decrypted_file_name = vdecrypt(file_name, password)[:-4]
        decrypted_content = b""
        start = 0
        while start < len(file_content):
            chunk = file_content[start:start + BLOCK_SIZE * BLOCK_MULTIPLIER]
            decrypted_content += decrypt(hkey, chunk)
            start += BLOCK_SIZE * BLOCK_MULTIPLIER
        logging.info("Decoded: " + file_name)
        return decrypted_file_name, decrypted_content
    except Exception as e:
        return e

# Streamlit UI
st.title("File Encryption/Decryption App")

mode = st.sidebar.selectbox("Select Mode", ["Encrypt", "Decrypt"])
password = st.sidebar.text_input("Password", type="password")
remove_files = st.sidebar.checkbox("Remove original files after processing")
maxWorker = st.sidebar.slider("Max Workers", 1, 20, 10)

uploaded_files = st.file_uploader("Choose files", accept_multiple_files=True)
process_files = st.button("Process Files")

if process_files:
    if not password:
        st.error("Password is required")
    else:
        result_files = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
            futures = []
            if mode == "Encrypt":
                for uploaded_file in uploaded_files:
                    file_content = uploaded_file.read()
                    file_name = uploaded_file.name
                    futures.append(executor.submit(encryptFile, file_content, file_name, password))
            elif mode == "Decrypt":
                for uploaded_file in uploaded_files:
                    file_content = uploaded_file.read()
                    file_name = uploaded_file.name
                    futures.append(executor.submit(decryptFile, file_content, file_name, password))

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    st.error(result)
                elif result:
                    file_name, file_content = result
                    st.download_button(
                        label=f"Download {file_name}",
                        data=file_content,
                        file_name=file_name,
                        mime="application/octet-stream"
                    )
        st.success("Processing completed")
