import psycopg2

try:
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="mysecretpassword",
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100),
            email VARCHAR(100),
            encrypted_data BYTEA
        );
    """)
    conn.commit()
    print("Table created successfully.")
except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()