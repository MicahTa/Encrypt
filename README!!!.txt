Encrypt.py V-1.0.0
Arguments are not nessisary to run the scrypt but you will be asked to awnser a few nessisary questions.


The arguments includeS

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