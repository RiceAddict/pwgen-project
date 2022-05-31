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

def opendoc():
    path = 'EULA.pdf'
    subprocess.Popen([path], shell=True)

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

def make_commpass_dict():
    with open('commonpassdict.txt', 'r') as commonpasses:
        passdict = {}
        i=1
        for password in commonpasses:
            passdict[password.strip()] = i
            i += 1
    #print('niceu')
    return passdict

#checks if entered or generated password is in the common pw dictionary, return True if passed the test, False if not
def pass_dict_check(password, the_dict):
    if password in the_dict:
        #print('no stop')
        return False
    else:
        #print('ok cool')
        return True
        

def popUpPass(text):
    wondow = Tk()
    wondow.title("Password Generator")

    def copy(strin):
        window.clipboard_clear()
        window.clipboard_append(strin)

    def checkStrength(password):
        
        common = pass_dict_check(password, poger)
        
        symbolos = r"`-=~!@#$%^&*()_+[]\}{|;':,./<>?"
        lower_letters = "qwertyuiopasdfghjklzxcvbnm"
        upper_letters = "QWERTYUIOPASDFGHJKLZXCVBNM"
        numberos = "0123456789"

        leno = False
        if len(password) >= 10:
            leno = True

        upper = False
        for c in password:
            if c in upper_letters:
                upper = True
                break

        lower = False
        for c in password:
            if c in lower_letters:
                lower = True
                break
        
        numbe = False
        for c in password:
            if c in numberos:
                numbe = True
                break
        
        symbo = False
        for c in password:
            if c in symbolos:
                symbo = True
                break

        if leno is True and upper is True and lower is True and numbe is True and symbo is True and common is True:
            customgood.config(text='Good password')
            return True
        else:
            customgood.config(text='Weak password')
            return False

    # Label frame.
    lf = LabelFrame(wondow, text="How many characters?")
    lf.pack(pady=20)

    # Create Entry Box for number of characters.
    myEntry = Entry(lf, font=("Helvetica", 12))
    myEntry.pack(pady=20, padx=20)

    makepw = Label(lf, text="Enter your own password")
    makepw.pack()
    customEntry = Entry(lf, font=("Helvetica", 12))
    customEntry.pack(pady=20, padx=20)

    customgood = Label(lf, text='')
    customgood.pack()

    checkbtn = Button(lf, text='Check Strength', command=lambda: checkStrength(customEntry.get()))
    checkbtn.pack(side=LEFT)
    
    clipBtn = Button(lf, text="Copy to Clipboard", command=lambda: copy(customEntry.get()))
    clipBtn.pack(side=RIGHT)

    # Create entry box for returned password.
    pwEntry = Entry(wondow, text="", font=("Helvetica", 12), bd=0, bg="systembuttonface")
    pwEntry.pack(pady=20)

    # Frame for buttons.
    myFrame = Frame(wondow)
    myFrame.pack(pady=20)

    # Create buttons
    myButton = Button(myFrame, text="Generate Password")
    myButton.grid(row=0, column=0, padx=10)

    clipBtn = Button(myFrame, text="Copy to Clipboard", command=lambda: copy(pwEntry.get()))
    clipBtn.grid(row=0, column=1, padx=10)

    answer = simpledialog.askstring("input string", text)
    wondow.destroy()
    return answer
    # good = 0
    # while good == 0:
    #     bong = checkStrength(customEntry.get())
    #     if bong is True:
    #         good = 1
    #         return customEntry.get()
    #     else:
    #         good = 0
            
            

#Initiate window
window = Tk()
window.update()

window.title("Password Vault")

def firstTimeScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x145')
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
    
    help_btn = Button(window, text="Help", command=opendoc)
    help_btn.pack(pady=5)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x150')
    savetxt= '''Save this key to be able to recover account
    write it down somewhere or sum'''
    lbl = Label(window, text=savetxt)
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

    help_btn = Button(window, text="Help", command=opendoc)
    help_btn.pack(pady=5)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x170')
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
            winsound.PlaySound("funnyresources/vineboom.mp3", winsound.SND_ASYNC)

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=5)

    botn = Button(window, text="Back To Login", command= loginScreen)
    botn.pack(pady=5)

    help_btn = Button(window, text="Help", command=opendoc)
    help_btn.pack(pady=5)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x390')
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

    help_btn = Button(window, text="Help", command=opendoc)
    help_btn.pack(pady=5)

def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(popUp(text1).encode(), encryptionKey)
        username = encrypt(popUp(text2).encode(), encryptionKey)
        password = encrypt(popUpPass(text3).encode(), encryptionKey)
        print(website, username, password)

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        

        vaultScreen()

    def removeEntry(iput):
        cursor.execute("DELETE FROM vault WHERE id = ?", (iput))
        winsound.PlaySound("funnyresources/baka.mp3", winsound.SND_ASYNC)
        db.commit()
        vaultScreen()

    window.geometry('900x550')
    window.resizable(True, True)
    
    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=1)

    ctrl_canvas = Canvas(main_frame, height=55)
    ctrl_canvas.pack(side=TOP)

    ctrl_frame = Frame(ctrl_canvas)

    ctrl_canvas.create_window((0, 0), window=ctrl_frame, anchor="nw")

    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=TOP,fill=BOTH,expand=1)

    lbl = Label(ctrl_frame, text="Password Vault")
    lbl.grid(row=0,column=1)
    
    btn = Button(ctrl_frame, text="New Login", command=addEntry)
    btn.grid(row=1, column=0, pady=10)

    help_btn = Button(ctrl_frame, text="Help", command=opendoc)
    help_btn.grid(row=1, column=1, pady=10)

    botn = Button(ctrl_frame, text="Logout", command= loginScreen)
    botn.grid(row=1, column=2, pady=10)
    
    second_frame = Frame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="n")
    
    my_scrollbar = ttk.Scrollbar(my_canvas, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))
    #lbl = Label(second_frame, text="Password Vault")
    #lbl.grid(row=0, column=1)

    lbl = Label(second_frame, text="Website")
    lbl.grid(row=0, column=0, padx=80)
    lbl = Label(second_frame, text="Username")
    lbl.grid(row=0, column=1, padx=80)
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=0, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break
            
            print(encryptionKey, 'keyo')
            lbl1 = Label(second_frame,text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i+3))
            lbl2 = Label(second_frame, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=1, row=(i+3))
            lbl3 = Label(second_frame, text=(decrypt(array[i][3], encryptionKey)), font=("Helvetica", 12))
            lbl3.grid(column=2, row=(i+3))

            btn2 = Button(second_frame, text="Copy Acc")#, command=partial(copyAcc, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = Button(second_frame, text="Copy Pass")#, command=partial(copyPass, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = Button(second_frame, text="Update")#, command=partial(updateEntry, array[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = Button(second_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=(i+3), pady=10)

            i = i + 1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute('SELECT * FROM masterpassword')

def main():
    window.iconbitmap("funnyresources/favicon.ico")
    global poger 
    poger = make_commpass_dict()
    if (cursor.fetchall()):
        loginScreen()
    else:
        # global encryptionKey
        # encryptionKey = 0
        firstTimeScreen()
    window.mainloop()

if __name__ == '__main__':
    main()