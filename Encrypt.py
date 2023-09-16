print ('Hello and welcome to Encrypt.py V-1.0.0 this software encrypts and decrypts copys of contents of the files, it does not copy the meta data and it does not encrypt the name of the folder/file. This software is free to use in any way to see fit. You can type --help for help. I bear no responsiblity for forgoten passwords, loss data, or any other damages acurred by using this code and scrypt.\nHave a wonderful day!\n\n -MT (;[===\n\n')

import sys
if '--help' in sys.argv:
    print ('''
    Encrypt.py V-1.0.0
    Arguments are not nessisary to run the scrypt but you will be asked to awnser a few nessisary questions.


    The arguments include

    -m or -mode, the options for this setting are e/encrypt or d/decrypt.
    This is to the scrypt wether you are encrypting the data or decrypting it.

    -i or -input, this is the files you want to be encrypted or decrypted.
    If you wish to encrpt or decrypt multibe files in diffrent locations such as /File1 and /Folder2 you can use this to include both of them by seperating them with a ':'.
    It is important to note that you can include both a directory (folder) or files and that all the files and directoies inside the original directory will also be encrypted/decrypted.

    -o or -output, this is the output directory.
    This is wear the contents of the scrypt will be moved to, this can only be one directory.

    -n or -outputName, this is the name of the directory everything is going to put everything into.
    The name connot contain the charitors /|\*:<>?, by defult this is just 'OUTPUT'

    -t or -timeStamp, this is if you want to add the date and time to the end of the output file.
    Simply type the option and it will turn it on.

    -O or -overRight, this is if you are saving it but the output directory already exists.
    If this is on and the folder already is there you program will close.
    Simply type the option to turn it on, by defult it is off.
    You only have this option if timestamp if off.

    -p or -password, this is the password duh.
    The password and salt are responisble for creating the key that decrypts and encrypts your files, so if you type in the wrong password to decrypt your files you'll either get an error or your files will look like gibberish.

    -s or - salt is the path to a salt file.
    Salting you key means that to generate the key you both need the password but youll also need the file.
    This is so that hackers both have to find that file and guess the password.
    However I suggest not using it if you dont properly understand it
    
    -GS or -generateSalt is if you want generate a salt file.
    Just type in the directory you want it to be in.
    Also this will altomatilly set the salt to what is generated.
    
    -EOI wich stands for Exit On Improper.
    This means that if you havn't defined all your options it will automatically close. This is for automated use such as running it on login.
    This also just skips asking the questions if you leave something on the defult setting.

    --help this just showes this screen.

    Thank you for using my totaly amazing code, remeber you are free to use this in anyway you want and I am not responisble for any loss you accure for using my scrypt.

    -MT (:[===
    ''')
    exit()

import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256  # Import the SHA-256 hash module
import hmac

exit_on_improper = False
if '-EOI' in sys.argv:
    exit_on_improper = True

password = None
output_file = None
to_encrpt = None
mode = None

# With defults
time_stamp = False

over_right = False
defined_over_right = False

output_name = 'OUTPUT'
defined_output_name = False

salt = b'\x9cmNx\xa5\xd6\xdf\x98\x10Zr\xe0\xd4\xeb\x989'



####################################################################################
################################## Pass arguments ##################################
####################################################################################

array = sys.argv
try:
    i = 0
    while i < len(sys.argv):
        ##### Prosses password #####
        if array[i] in ['-p', '-password']:
            i += 1
            password = array[i]
        ##### Prosses output #####
        elif array[i] in ['-o', '-output']:
            i += 1
            if os.path.isdir(array[i]):
                output_file = array[i]
            else:
                password = None
                print ('Output file is not valid')
                if exit_on_improper:
                    exit()
        ##### Prosses input #####
        elif array[i] in ['-i', '-input']:
            i += 1
            to_encrpt = array[i].split(':')
            all_good = True
            for f in to_encrpt:
                if not os.path.exists(f):
                    all_good = False
            if not all_good:
                to_encrpt = None
                if exit_on_improper:
                    exit()
        ##### Prosses mode #####
        elif array[i] in ['-m', '-mode']:
            i += 1
            mode = array[i] # either encrypt/e, decrypt/d
            if mode not in ['e', 'encrypt', 'd', 'decrypt']:
                mode = None
                if exit_on_improper:
                    exit()
        ##### Prosses output name #####
        elif array[i] in ['-n', '-outputName']:
            i += 1
            if not ('/' in array[i] or '\\' in array[i] or ':' in array[i] or '?' in array[i] or '\"' in array[i] or '|' in array[i] or '*' in array[i] or '<' in array[i] or '>' in array[i] or '*' in array[i]):
                output_name = array[i]
                defined_output_name = True
            elif exit_on_improper:
                exit()
        ##### Gerneate Salt #####
        elif array[i] in ['-GS', '-generateSalt']:
            i += 1
            tmp = f'{array[i]}'
            if os.path.exists(array[i]):
                goo = True
                s = 0
                while goo == True:
                    if os.path.exists(f'{tmp}/SALT-{s}.salt'):
                        s += 1
                    else:
                        tmp = f'{tmp}/SALT-{s}.salt'
                        goo = False
                        try:
                            with open(f'{array[i]}/SALT-{s}.salt', 'wb') as file:
                                tmp = os.urandom(16)
                                file.write(tmp)
                                salt = tmp
                                print (f'Generated salt file as {array[i]}/SALT-{s}.salt')
                        except:
                            print ('ERROR creating salt file')
                            exit()
            elif exit_on_improper:
                exit()
        ##### Use salt file #####
        elif array[i] in ['-s', '-salt']:
            i += 1
            if os.path.isfile(array[i]):
                try:
                    with open(array[i], 'rb') as file:
                        salt = file.read()
                except:
                    print ('ERROR unable to read salt file')
                    exit()
            elif exit_on_improper:
                exit()
        ##### Prosses overight #####
        elif array[i] in ['-O', '-overRight']:
            over_right = True
            defined_over_right = True
        ##### Prosses time stamp #####
        elif array[i] in ['-t', '-timeStamp']:
            time_stamp = True
        i += 1
except Exception as e:
    print ('Improper arguments please manually input text\n', e)
    if exit_on_improper:
        exit()


# Handle exiting if EOI and varible is not defined
if exit_on_improper and ((mode is None) or (password is None) or (output_file is None) or (to_encrpt is None)):
    print ("Exit on improper was on and not all settings were defined type --help for more information")
    exit()

####################################################################################
################################### Ask questions ##################################
####################################################################################

# Don't ask questions if EOI is on
if not exit_on_improper:
    # Set things up if they wernt defined eailer
    # Prosses mode
    if mode is None:
        goo = True
        while goo:
            print ('')
            mode = input('Enter \'e\' to encrypt and \'d\' to decrypt: ')
            if mode in ['e', 'encrypt', 'd', 'decrypt']:
                goo = False
            else:
                print ('Not valid please type either \'e\' to encrypt and \'d\' to decrypt')
                

    # Prosses password
    if password is None:
        print ('')
        import getpass
        goo = True
        while goo:
            password = getpass.getpass("Enter your password: ")
            repassword = getpass.getpass("Reenter your password: ")
            if password != repassword:
                print ('Passwords do not match!!')
            else:
                goo = False

    # Prosses salt
    if salt == b'\x9cmNx\xa5\xd6\xdf\x98\x10Zr\xe0\xd4\xeb\x989':
        print ('')
        if 'y' == input('Would you like to salt your key, \'y\' for yes \'n\' for no: '):
            if 'y' == input('Would you like to generate a salt, \'y\' for yes \'n\' for no: '):
                goo = True
                while goo:
                    tmp_dir = input('Type directory you want to generate salt file in, type c to cancel: ')
                    if 'c' == tmp_dir:
                        goo = False
                    else:
                        if os.path.exists(tmp_dir):
                            goo = True
                            s = 0
                            while goo == True:
                                if os.path.exists(f'{tmp_dir}/SALT-{s}.salt'):
                                    s += 1
                                else:
                                    try:
                                        with open(f'{tmp_dir}/SALT-{s}.salt', 'wb') as file:
                                            tmp = os.urandom(16)
                                            file.write(tmp)
                                            salt = tmp
                                            print (f'Generated salt file as {tmp_dir}/SALT-{s}.salt')
                                            goo = False
                                    except:
                                        print ('ERROR creating salt file, make shure that the directory you listed exists')
            else:
                goo = True
                while goo:
                    tmp = input('Enter salt file, type \'c\' to cancel: ')
                    if tmp == 'c':
                        goo = False
                    else:
                        if os.path.isfile(tmp):
                            try:
                                with open(tmp, 'rb') as file:
                                    salt = file.read()
                                    goo = False
                            except:
                                print ('ERROR unable to read salt file')

    # Prosses input
    if to_encrpt is None:
        goo = True
        print ('')
        while goo:
            all_good = True
            to_encrpt = input('Add files/folders to be changed, seperate mutible files/folders with \':\': ').split(':')
            for f in to_encrpt:
                if not os.path.exists(f):
                    all_good = False
            if all_good:
                goo = False
            else:
                print ('Enter a valid input file/directory.')

    # Prosses output
    if output_file is None:
        print ('')
        goo = True
        while goo:
            output_file = input('Output file: ')
            if os.path.isdir(output_file):
                goo = False
            else:
                print ('Not valid directory please enter a real folder.')

    # Prosses output name
    if output_name == 'OUTPUT' and not defined_output_name:
        goo = True
        while goo:
            output_name = input('Type name of folder the contents will be added too: ')
            if not ('/' in output_name or '\\' in output_name or ':' in output_name or '?' in output_name or '\"' in output_name or '|' in output_name or '*' in output_name or '<' in output_name or '>' in output_name or '*' in output_name):
                goo = False
            else:
                print ('Please enter a valid name, it cannot contain /|\\*:<>?')

    # Prosses time stamp
    if time_stamp == False:
        goo = True
        print ('')
        while goo:
            tmp = input('Add time stamp to files, type y for yes and n for no: ')
            if tmp in ['n', 'N']:
                time_stamp = False
                goo = False
            elif tmp in ['y', 'Y']:
                time_stamp = True
                defined_over_right = True
                goo = False
            else:
                print ('Please enter something valid.')


    # Prosses over right
    if time_stamp is True:
        over_right = False
    if over_right is False and not defined_over_right:
        goo = True
        print ('')
        while goo:
            tmp = input('Over-right old output files, type y for yes and n for no: ')
            if tmp in ['n', 'N']:
                over_right = False
                goo = False
            elif tmp in ['y', 'Y']:
                over_right = True
                goo = False
            else:
                print ('Please enter something valid.')

####################################################################################
################################### Generate key ###################################
####################################################################################

# Generate key
print ('\nGenerating Key....')
try:
    key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000, prf=lambda p, s: hmac.new(p, s, sha256).digest())
except:
    print ('ERROR generating key, check the salt')
    exit()
print (key)
print ('\nProcessing files')

####################################################################################
###################################### Encrypt #####################################
####################################################################################
# Function to pad the data to be encrypted to a multiple of 16 bytes (AES block size)
def pad_data(data):
    block_size = 16
    return data + (block_size - len(data) % block_size) * bytes([block_size - len(data) % block_size])

# Function to encrypt data with AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


####################################################################################
###################################### Decrypt #####################################
####################################################################################
# Remove padding from the decrypted data
def unpad_data(data):
    return data.rstrip(bytes([data[-1]]))

def decrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

####################################################################################
###################################### __crypt #####################################
####################################################################################
# Once you have the srs and dst file read __crypt and write
def copy(encrypt, srs, dst):
    try:
        # Read the binary
        with open(srs, 'rb') as read_file:
            read_bin = read_file.read()
        if encrypt:
            # Pad and encrypt
            padded_data = pad_data(read_bin)
            __crypted_data = encrypt_data(padded_data, key)
        else:
            # Decrypt and unpad
            __crypted_data = decrypt_data(read_bin, key)
            unpadded_data = unpad_data(__crypted_data)
            __crypted_data = unpadded_data
        # Write the copy
        print (f'Copied file: {dst}')
        with open(f'{dst}/{os.path.basename(srs)}', 'wb') as file:
            file.write(__crypted_data)
    except:
        print (f'ERROR could not __crypt file {srs}')
        #print (f'ERROR could not') # LOL
    
    
# This is pretty much exactly the same as some old code and I forgot how it worked so theres tons of comments
# (:
def en_de_crypt(encrypt, srs, dst, dir):
    # make directory with name if dir is true
    if dir:
        ndst = srs.split("/")[-1]#('\\', 1)[-1]
        try:
            os.mkdir((dst + "/" + ndst))
        except:
            print (f'ERROR couldn\'t make directory {dst + "/" + ndst}')
        dst += "/" + ndst
    
    # If its a file copy
    if os.path.isfile(srs):
        copy(encrypt, srs, dst)

    # If its a directory
    elif os.path.isdir(srs):
        # Get file list
        filelist = (os.listdir(srs))
        for i in range (len(filelist)):
            # 'Just in kase'
            name = filelist[i]
            # change the file list to also include the source
            filelist[i] = (srs + "/" + filelist[i])
            # if its a dir
            if os.path.isdir(filelist[i]):
                # make the name for new dir
                ndst = (dst + "/" + name)
                # Make the direcory
                try:
                    os.mkdir(ndst)
                except:
                    print (f'ERROR couldn\'t make directory {ndst}')
                # Re run this code in that new directory
                en_de_crypt(encrypt, filelist[i], ndst, False)
            # if its a file
            elif os.path.isfile(filelist[i]):
                # just copy
                copy(encrypt, filelist[i], dst)


####################################################################################
################################### OUTPUT FILE ####################################
####################################################################################


# Add timestamp
if time_stamp:
    from datetime import datetime
    current_datetime = datetime.now()
    output_name += current_datetime.strftime("_%m-%d-%y_%H-%M-%S")

# Stop if overight is enabled and output directoriy exists
elif not over_right:
    if os.path.isdir(f'{output_file}/{output_name}'):
        print ('ERROR over-right is off and output file aleady exists')
        exit()

# Make output direcroie
if not os.path.isdir(f'{output_file}/{output_name}'):
    try:
        os.mkdir(f'{output_file}/{output_name}')
    except:
        print ('ERROR Could not create output directory')
        exit()
output_file = (f'{output_file}/{output_name}')


####################################################################################
######################################## RUN #######################################
####################################################################################

if mode in ['encrypt', 'e']:
    en = True
else:
    en = False

# Run __crypt
for i in to_encrpt:
    if os.path.isfile(i):
        en_de_crypt(en, i, output_file, False)
    elif os.path.isdir(i):
        en_de_crypt(en, i, output_file, True)
    else:
        # Just in case (:
        print (f'ERROR {i} does not exits')

print ('\n\nDONE!!!\n\n\n')