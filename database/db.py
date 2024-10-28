import mysql.connector

# Connection
def connectDB():
    connection = None
    try:
        connection = mysql.connector.connect(
            host='192.168.1.160',
            user='admin',
            password='password',
            database='dbPassMan',
            port='3306'
        )
        if connection.is_connected():
            print("Connected to MySQL Server")

    except mysql.connector.Error as e:
        print(f"Error: {e}")
    return connection




# Database management

def create_user_credentials():
    connection = connectDB()
    if connection is not None:
        cursor = connection.cursor()
        cursor.execute("""
        CREATE TABLE user_credentials(
                    id SMALLINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(30) NOT NULL UNIQUE,
                    email VARCHAR(60) NOT NULL UNIQUE,
                    salt BINARY(32),
                    hash VARCHAR(45),
                    date_added DATETIME DEFAULT NOW()
                    );
                    """)

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


# drop_table('user_credentials')
# create_user_credentials()