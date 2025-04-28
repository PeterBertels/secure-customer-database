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
    cursor.execute("INSERT INTO customers (name, email) VALUES (%s, %s)", ("John Doe", "john@example.com"))
    conn.commit()
    cursor.execute("SELECT * FROM customers")
    rows = cursor.fetchall()
    for row in rows:
        print(row)
except Exception as e:
    print(f"Error: {e}")
finally:
    cursor.close()
    conn.close()
