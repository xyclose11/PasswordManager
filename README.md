# PasswordManager
One Day Project

## What it does
- Allows user to create an account
- Add passwords
- View password names
- Delete passwords

## Specifics
- I chose to compare the password hashes for the user account login rather than encrypting and decrypting them.
- As for the actual passwords that are stored, I went with the cryptography library which includes Fernet.
- I ended up setting up a Key Derivation function so that the user's passwords would be consistently salted with the same salt and their passwords would be derived from their master password.
- This all links to a SQLite3 database

## Details
- First "project" that isn't part of a course/class
- No tutorials were used, just documentation and online searches
- NOT FULLY DEVELOPED as I am still learning

### Disclaimer
I am a 1st-year Computer Science student with limited experience in Python, so there will likely be many bugs and functionality errors. 

This project is about learning how different aspects of Software Development interact and working through those problems as they come up, and is not intended to be used to securly save passwords for anyone.

