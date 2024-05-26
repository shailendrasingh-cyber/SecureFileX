import streamlit as st
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures

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

def encryptFile(filePath, password):
    try:
        logging.info("Started encoding: " + filePath.name)
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        encryptPath = Path(filePath.parent.resolve().as_posix() + "/" + vencrypt(filePath.name, password) + ".enc")
        if encryptPath.exists():
            encryptPath.unlink()
        with open(filePath, "rb") as input_file, encryptPath.open("ab") as output_file:
            content = input_file.read(BLOCK_SIZE * BLOCK_MULTIPLIER)
            while content != b'':
                output_file.write(encrypt(hkey, content))
                content = input_file.read(BLOCK_SIZE * BLOCK_MULTIPLIER)
            logging.info("Encoded " + filePath.name)
            logging.info("To " + encryptPath.name)
    except Exception as e:
        st.error(e)

def decryptFile(filePath, password):
    logging.info("Started decoding: " + filePath.name)
    try:
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        decryptFilePath = Path(filePath.parent.resolve().as_posix() + "/" + vdecrypt(filePath.name, password)[:-4])
        if decryptFilePath.exists():
            decryptFilePath.unlink()
        with filePath.open("rb") as input_file, decryptFilePath.open("ab") as output_file:
            values = input_file.read(BLOCK_SIZE * BLOCK_MULTIPLIER)
            while values != b'':
                output_file.write(decrypt(hkey, values))
                values = input_file.read(BLOCK_SIZE * BLOCK_MULTIPLIER)
        logging.info("Decoded: " + filePath.name)
        logging.info("TO: " + decryptFilePath.name)
    except Exception as e:
        st.error(e)

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
        with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
            if mode == "Encrypt":
                for uploaded_file in uploaded_files:
                    file_path = Path(uploaded_file.name)
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    executor.submit(encryptFile, file_path, password)
                    if remove_files:
                        file_path.unlink()
            elif mode == "Decrypt":
                for uploaded_file in uploaded_files:
                    file_path = Path(uploaded_file.name)
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    executor.submit(decryptFile, file_path, password)
                    if remove_files:
                        file_path.unlink()
        st.success("Processing completed")
