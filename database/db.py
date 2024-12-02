import mysql.connector
from os import environ

# Connection
def connectDB():
    connection = None
    host, user, password, database, port = environ.get('dbCreds').split('/')
    try:
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port=port
        )
        if connection.is_connected():
            print("Connected to MySQL Server")

    except mysql.connector.Error as e:
        print(f"Error: {e}")
    return connection


    # Database management
# Table creation
def create_user_credentials():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE user_credentials(
                    id SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(30) NOT NULL UNIQUE,
                    email VARCHAR(60) NOT NULL UNIQUE,
                    type ENUM ('user', 'admin') DEFAULT 'user',
                    salt BINARY(32),
                    hash VARCHAR(45),
                    master VARCHAR(45),
                    masterSalt BINARY(32),
                    date_added DATETIME DEFAULT NOW()
                    );
                    """)

def create_user_preferences():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE user_preferences(
                    user_id SMALLINT UNSIGNED,
                    theme ENUM ('light', 'dark', 'sky') DEFAULT 'sky', 
                    FOREIGN KEY (user_id) REFERENCES user_credentials(id) ON DELETE CASCADE
                    );
                    """)
        
def create_user_data():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE user_data(
                    entry_id SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id SMALLINT UNSIGNED,
                    account VARCHAR(255),
                    ciphertext BLOB,
                    iv BLOB,
                    salt BINARY(32),
                    iteration INT,
                    favorite BOOL DEFAULT FALSE,
                    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES user_credentials(id) ON DELETE CASCADE
                    );
                    """)

def create_audit_log():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE audit_log(
                    user_id SMALLINT UNSIGNED,
                    event ENUM ('logged in', 'added credentials', 'removed credentials', 'set master pass', 'credentials accessed'),
                    event_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    access_ip VARCHAR(32),
                    FOREIGN KEY (user_id) REFERENCES user_credentials(id) ON DELETE CASCADE
                    );
                    """)

# Triggers
def preferences_trigger():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""CREATE TRIGGER create_prefs
             AFTER INSERT ON user_credentials
             FOR EACH ROW
             BEGIN
             INSERT INTO user_preferences (user_id, theme)
             VALUES (NEW.id, 'sky');
             END;""")
        

# Table management
def drop_table(table):
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute(f"DROP TABLE {table}")

def clear_table(table):
        connection = connectDB()
        if connection is not None:
            cursor = connection.cursor()
            cursor.execute(f" TRUNCATE TABLE {table} ")

def show_tables():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("SHOW TABLES")

# drop_table('user_preferences')
# drop_table('user_data')
# drop_table('audit_log')
# drop_table('user_credentials')

# create_user_credentials()
# create_user_preferences()
# create_user_data()
# preferences_trigger()
# create_audit_log()