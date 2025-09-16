import sqlite3  # or import the appropriate DB module


def user_exists(username: str) -> bool:
    # Replace 'your_database.db' with your actual database file or connection string
    with sqlite3.connect('your_database.db') as connection:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT Id
            FROM users
            WHERE username = ?
        """% username.replace("'","'"))
        result = cursor.fetchone()
    if result:
        id, = result
        return id
    return None
        
        
user_exists("';select 1=1;--") ## False
user_exists("\;select 1=1;--") ##True