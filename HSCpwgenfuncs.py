#version unga bunga 0.3
import random

#generate a password by picking from set of characters
def generate(pass_dict):
    '''Takes common pass dict, generates password and checks if it is too common.

        Parameters:
                pass_dict(dict): Dictionary of 10000 common passwords.

        Returns:
                new_pass(str): Suggested password for the user to copy.
    '''
    some_chars = r"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM`1234567890-=~!@#$%^&*()_+[]\}{|;':,./<>?"
    new_pass = ''
    pass_len = int(input("how long bro: "))
    for each_letter in range(pass_len):
        new_pass += some_chars[random.randrange(0,len(some_chars))]
    
    good = 0    #intialise for internal check
    while good == 0:
        if set(list(new_pass)) == new_pass[0]:
            generate(pass_dict)
        elif pass_dict_check(new_pass, pass_dict) is False:
            generate(pass_dict)
        else:
            good = 1
    return new_pass

#make a dictionary of common passwords for instant checking, made on startup
def make_commpass_dict():
    with open('commonpassdict.txt', 'r') as commonpasses:
        passdict = {}
        i=1
        for password in commonpasses:
            passdict[password.strip()] = i
            i += 1
    print('niceu')
    return passdict

#checks if entered or generated password is in the common pw dictionary, return True if passed the test, False if not
def pass_dict_check(password, the_dict):
    if password in the_dict:
        print('no stop')
        return False
    else:
        print('ok cool')
        return True

def strengthCheck(password):
    symbols = r"`-=~!@#$%^&*()_+[]\}{|;':,./<>?"
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
        if c in symbols:
            symbo = True
            break

    if leno is True and upper is True and lower is True and numbe is True and symbo is True:
        return True
    else:
        return False

#allow user to enter a new password, includes loop to not allow common pw to be accepted
def add_pass(the_dict):
    entered_pass = input('enter a password: ')
    if strengthCheck(entered_pass) is True and pass_dict_check(entered_pass, the_dict) is True:
        print("poggers added")
    else:
        print('again')
    
def encrypt():
    pass

def decrypt():
    pass

poger = make_commpass_dict()
# print(generate(poger))
# pass_dict_check('uhfh88h', poger)
add_pass(poger)
