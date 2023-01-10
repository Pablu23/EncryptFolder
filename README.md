# EncryptFolder

A simple console Application to encrypt the contents of a folder.

Features:
1. Encrypts whole Folder
2. Uses multithreading to speed up Encryption / Decryption Process
3. Saves file names encrypted with same password in binary, and restores names on decrypt
4. Password is salted and hashed and saved with salt in binary, for password checking before decrypting
5. Responsive Loading Screen for files of a certain size
6. Commented code for easy understanding