import sqlite3, hashlib
from tkinter import *
from tkinter import ttk
from PIL import Image,ImageTk
from tkinter import simpledialog
from functools import partial
import uuid
import re
import subprocess
import pyperclip
import base64
import winsound
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()

unique = subprocess.check_output("wmic csproduct get uuid").decode() #get permanent UUID of device
match = re.search(r"\bUUID\b[\s\r\n]+([^\s\r\n]+)", unique)
if match is not None:
    unique = match.group(1)
    if unique is not None:
        # Remove the surrounding whitespace (newlines, space, etc)
        # and useless dashes etc, by only keeping hex (0-9 A-F) chars.
        unique = re.sub(r"[^0-9A-Fa-f]+", "", unique)

def hashPassword(passw):
    hash1 = hashlib.sha3_512(passw)
    hash1 = hash1.hexdigest()

    return hash1

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes: #joe mama
    return Fernet(token).decrypt(message)

the_real_salt = hashPassword(unique.encode()) #use permanent UUID, hash it and use as salt

salt = bytes(the_real_salt.encode())

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA3_512(),
    length=32,
    salt=salt,
    iterations=1000000,
    backend=backend
)

encryptionKey = base64.urlsafe_b64encode(kdf.derive(the_real_salt.encode())) #permanent UUID used to derive encryption key, no need to delete database if changing master

#database code
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

#Create PopUp
def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

#Initiate window
window = Tk()
window.update()

window.title("Password Vault")

def firstTimeScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')
    lbl = Label(window, text="Choose a Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl.config(text="Passwords dont match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')
    lbl = Label(window, text="Save this key to be able to recover account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=5)

    def done():
        vaultScreen()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=5)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')
    lbl = Label(window, text="Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            firstTimeScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Wrong Key')

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x372')
    stev = Image.open("funnyresources/SteveMinecraft.png")
    stev = stev.resize((120, 120))
    stev = ImageTk.PhotoImage(stev)
    stev.image = stev

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)
    
    def getMasterPassword():
        Pss = txt.get().encode()
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            print(encryptionKey)
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")
            winsound.PlaySound("funnyresources/vineboom.mp3", winsound.SND_ASYNC)

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)
    
    testolab = Label(window, text='')
    testolab.pack(pady=10)

    def bruh():
        def bro():
            testolab.config(text='')
        testolab.config(text='wow insane')
        testolab.after(2000,lambda: bro())

    ponger = Button(window, image=stev, command=lambda: bruh())#, height=5, width=5)
    ponger.pack(pady=5, side= TOP)
    quit_btn = Button(window, text='quit', command=window.quit)
    quit_btn.pack(pady=10)

def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUp(text3).encode(), encryptionKey)
        print(website, username, password)

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    window.geometry('750x550')
    window.resizable(True, True)
    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break
            
            print(encryptionKey, 'keyo')
            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(window, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i+3))

            btn = Button(window, text="Delete", command=  partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i+3), pady=10)

            i = i +1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute('SELECT * FROM masterpassword')

def main():
    window.iconbitmap("funnyresources/favicon.ico")
    sg = ttk.Sizegrip(window)
    sg.grid(row=1, sticky=SE)
    if (cursor.fetchall()):
        loginScreen()
    else:
        # global encryptionKey
        # encryptionKey = 0
        firstTimeScreen()
    window.mainloop()

if __name__ == '__main__':
    main()