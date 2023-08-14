import sqlite3
import base64
import os
import hashlib
from hashlib import blake2b
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#Connecting to the local database
try:
    con = sqlite3.connect("data2.db", timeout=150)

    cur = con.cursor()

except sqlite3.Error as error:
    print("Database Failure", error)

#Getting user input to check if the username is valid
username = input("Username: ")

try:
    dbCheck = cur.execute('''SELECT username FROM users WHERE username=(?)''',[username])

except sqlite3.Error as error:
    print("Username SQL Failure", error)

#We need to check if this is vulnerable to duplicate usernames 
usernameData = dbCheck.fetchone()

#Hashes the master password
def hash (password):

    #Encode
    passwordEncode = password.encode()

    #Encrypt Plaintext
    hash = blake2b()
    hash.update(passwordEncode)
    passwordHash = hash.hexdigest()

    #Overwrite Plaintext variable
    password = None

    return passwordHash

#Encrypts passwords 
def encrypt (userPassword,username,userId):

    userSalt = cur.execute('''SELECT pepper.salt FROM pepper INNER JOIN users ON pepper.id=users.id''')

    salt = userSalt.fetchone()

    key = keyDerive(salt[0], username, userId)
    f = Fernet(key)
    encPass = f.encrypt(userPassword)

    return encPass

def decrypt (plainPass, username,userId):
    userSalt = cur.execute('''SELECT pepper.salt FROM pepper INNER JOIN users ON pepper.id=users.id''')

    salt = userSalt.fetchone()

    key = keyDerive(salt[0], username, userId)
    f = Fernet(key)
    decPass = f.decrypt(plainPass)
    return decPass

def keyDerive(userSalt,username,userId):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=userSalt,
        iterations=500000,
    )

    userPasswordHash = cur.execute('''SELECT password FROM users WHERE username=? AND id=?''',[username,userId])
    hash = userPasswordHash.fetchone()

    userKey = base64.urlsafe_b64encode(kdf.derive(hash[0].encode()))

    return userKey


#Creates a new SQL table
def newUserTable(username, userId):
    cur.execute('''CREATE TABLE ''' + username + str(userId) + ''' (id INTEGER PRIMARY KEY AUTOINCREMENT, passName TEXT, password BLOB)''')

    userSalt = os.urandom(16)

    cur.execute('''INSERT INTO pepper (salt) VALUES (?)''', [userSalt])

#Inputs a password into SQL table
def deposit(username, userId, userPasswordName, userPassword):
    
    userPasswordEncode = userPassword.encode()

    securePasswordValue = encrypt(userPasswordEncode, username, userId)

    cur.execute('''INSERT INTO ''' + username + str(userId) +''' (passName, password) VALUES (?, ?)''', [userPasswordName, securePasswordValue])
    con.commit()

#Retrieves all passwordNames
def retrieveAll(username, userId):
    return cur.execute('''SELECT passName FROM ''' + username + str(userId) +''' ''')

#Retrieves a single passwordName
def retrieve(username, userId, userView):
    plainPass = cur.execute('''SELECT password FROM ''' + username + str(userId) + ''' WHERE passName= (?)''', [userView])

    plainPass = plainPass.fetchone()[0]

    plainPassValue = decrypt(plainPass, username, userId)

    return plainPassValue.decode()

#Deletes a single password row
def delete(username, userId, userDelete):
    cur.execute('''DELETE FROM ''' + username + str(userId) + ''' WHERE passName=(?)''', [userDelete])
    con.commit()
    return "Success"

#Deletes all password rows for user
def deleteAll(username, userId):
    cur.execute('''DELETE FROM ''' + username + str(userId) + '''''')
    con.commit()
    return "Success"

#Checking to see if the username exists
if usernameData:

    #Using "getpass" I am able to hide the users password when they are typing
    #You could also do something with the intention of creating a newline before they start typing to get a similar effect
    authPassword = getpass()

    #Hashing the users password
    securePassword = hash(authPassword)

    #We need to figure out a way to encrypt the password before we are able to see it.

    #We could possibly check if the passwords match in SQL instead

    #Gets the existing password for that user !!! Vulnerable to duplicate usernames !!!
    hashAuthPass = cur.execute('''SELECT password FROM users WHERE username IS (?)''', [username])

    #Loops through all password hashes for the desired username
    for i in hashAuthPass.fetchall():
        escapeSeq = "0"

        #Checks if the entered password is = to an existing password
        if securePassword in i:
            
            while True:
                
                if escapeSeq != "0":
                    exit(1)

                currentUser = cur.execute('''SELECT id FROM users WHERE username IS (?) AND password IS (?)''', [username, securePassword])
                userId = currentUser.fetchone()[0]

                userChoice = input("Press 1 to input a password | 2 to view a password | 3 to delete a password")
                
                if userChoice == '1':

                    userPasswordName = input("Please enter the name of the application where the password would be used: ")
                    userPassword = getpass("Enter your password here: ")

                    deposit(username, userId, userPasswordName, userPassword)

                elif userChoice == '2':

                    userView = input("Press 1 to view a list of password names | Or enter your desired name: ")

                    if userView == '1':

                        results = retrieveAll(username, userId)

                        for row in results.fetchall():
                            print(row)

                    else:
                        results = retrieve(username, userId, userView)

                        print(results)

                elif userChoice == '3':

                

                    userDelete = input("Enter 1 to view password names | Press 999 to delete all passwords! | Enter the name of the password you want to delete: ")

                    if userDelete == '1':
                        results = retrieveAll(username, userId)

                        print(results.fetchall())

                    elif userDelete == '999':
                        confirm = input("Are you sure you want to DELETE ALL of your PASSWORDS? THIS CANNOT BE UNDONE. ENTER 'DElEtE !@#' TO DELETE ALL | Enter '1' to exit.")
                        if confirm == '1':
                            break
                        elif confirm == 'DElEtE !@#':
                            results = deleteAll(username, userId)
                            print(results)
                            

                    else:
                        results = delete(username, userId, userDelete)

                        print(results)
                escapeSeq = input("Press 0 to continue | Press any other key to quit | ")


        elif securePassword not in i:
            print("Incorrect Password|")

else:

    newAccount = input("Do you want to create an account? (yes,sure,1)")

    if newAccount.lower() in ("yes", "sure", "1"):

        password = getpass("Create your password: ")
        securePassword = hash(password)

        cur.execute('''INSERT INTO users (username, password) VALUES (?, ?)''', [username,securePassword])

        currentUser = cur.execute('''SELECT id FROM users WHERE username IS (?) AND password IS (?)''', [username, securePassword])
        userId = currentUser.fetchone()[0]
        newUserTable(username, userId)

        #Saving and Closing the Database
        con.commit()
        con.close()

exit(1)







