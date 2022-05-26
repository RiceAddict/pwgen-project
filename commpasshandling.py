#handling common passwords
def createpassdict():
    with open('commonpassdict.txt', 'r') as commonpasses:
        passdict = {}
        i=1
        for password in commonpasses:
            passdict[password.strip()] = i
            i += 1
    print('niceu')
    return passdict
