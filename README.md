# ECE422_server_client_encryption
How to run:
$> make
then copy this line and enter
$> export LD_LIBRARY_PATH=D_LIBRARY_PATH:.

all communication is done via TEA. with keys exchanged via Diffie Hellman

for Server
$> java EncryptedServer
will be prompted if you want to add users (y/n)
if y
    user information is encrypted with TEA into a shadowTable
    $ Username: <username>
    $ Password: <password>
    then will be prompted to keep adding (y/n)
else
    server now just sits there nd waits for clients. Notifies if a client is trying to connect, and when a client disconnects

for Client
$ Username: <username>
$ Password: <password>
if successful, client is prompted for filename, otherwise asked if they would like to connect again
$ Filename: <filename to be read, can only read local files of the Server>
informed if read was successful or not and asked if client likes to do again
all files read will be stored in the user's file labeled under their username

