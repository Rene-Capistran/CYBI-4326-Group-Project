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
You will need to set up mysql server somewhere, so do that and create a database to connect to. have your DB credentials handy.

Afterwards, you'll need to set up some...
# Environment Variables
Assuming you're using a windows machine to run the backend, start by finding 'edit the system environment variables' within the start menu.
![image](https://github.com/user-attachments/assets/9dac2ccb-dd97-4872-8ab1-3370f9d916a8)

Next, press 'Environment Variables...' and 'Edit...' (Just user variables should be fine).

![image](https://github.com/user-attachments/assets/f1a7785e-f883-450c-a2a4-a8cb28880a5e)

![image](https://github.com/user-attachments/assets/7e718fda-a8ca-485e-86fa-4131d6f07f1e)


From here, you will need to create two environment variables.

### First, your CSRF token:

  under 'Variable name', type 'CSRFtoken'. You can make the value whatever you'd like.

![image](https://github.com/user-attachments/assets/ee015e04-dc0c-4151-a6c1-da62e354ccb6)

  
### The second will be your database credentials:

  For this Variable name, type 'dbCreds'. In the value box, you will add your credentials in this format: 
  
    [database ip]/[username]/[password]/[database name]/[port No.]

  ![image](https://github.com/user-attachments/assets/6b5f5120-15ed-498d-aef9-489aab62edfd)
    
  For example: 192.168.1.20/billy/P@ssw0rd1/coolDatabaseName/3306

  #### It is important to keep in-mind that the credentials must be delimited by forward-slashes.

## To run the project
  
First, ensure that your server running mySQL server is running.

Next, go to db.py and uncomment lines 127-131

![image](https://github.com/user-attachments/assets/51422d86-5104-4102-9b8f-d439e3045ae3)

![image](https://github.com/user-attachments/assets/d60f692f-c667-46d3-bb92-438e29fb1c66)

## Remember to re-comment this after the tables have been created

Then, run db.py to create the database tables. If you get no errors, the tables were created successfully.

![image](https://github.com/user-attachments/assets/182217a2-5a0c-4709-9631-bd8d4f64243c)

Finally, run app.py

You should be able to connect to the application via localhost at port 12345

    127.0.0.1:12345

![image](https://github.com/user-attachments/assets/45e1e6f8-f87f-4a0d-a95c-4103d403a0cb)

