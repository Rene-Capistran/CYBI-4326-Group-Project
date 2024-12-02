# CYBI-4326-Group-Project (Memorize)


# Dependencies
### python modules:
    Flask

    Flask-WTF

    WTForms

    argon2-cffi

    pycryptodome

    mysql-connector-python

## Notice: Be sure to have pip up to date! (pip install --upgrade pip)
### Database server:
You will need to set up mysql server somewhere, so do that and have your DB credentials handy.

Afterwards, you'll need to set up some...
# Environment Variables
Assuming you're using a windows machine to run the backend, start by finding 'edit the system environment variables' within the start menu.

Next, press 'Environment Variables...' and 'Edit...' (Just user variables should be fine).

From here, you will need to create two environment variables. First, your CSRF token:

  under 'Variable name', type 'CSRFtoken'. You can make the value whatever you'd like.
  
The second will be your database credentials:

  For this Variable name, type 'dbCreds'. In the value box, you will add your credentials in this format: 
  
    [database ip]/[username]/[password]/[database name]/[port No.]
  
  For example: 192.168.1.20/billy/password/coolDatabaseName/3306
    
  It is important to keep in-mind that the credentials must be delimited by forward-slashes.
