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
- No tutorials were used, only documentation
- An attempt to branch my learning to something that I want to do without guidance

