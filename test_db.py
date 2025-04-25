import pyodbc

def test_portal_connection():
    try:
        connection_string = (
            "DRIVER={ODBC Driver 17 for SQL Server};"
            "SERVER=192.168.1.40;"
            "DATABASE=PORTAL_EYV;"
            "Trusted_Connection=yes;"
        )
        conn = pyodbc.connect(connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        print(f"Connected to PORTAL_EYV: {version}")
        conn.close()
        return True
    except Exception as e:
        print(f"Connection to PORTAL_EYV failed: {str(e)}")
        return False

def test_editor_connection():
    try:
        connection_string = (
            "DRIVER={ODBC Driver 17 for SQL Server};"
            "SERVER=192.168.1.40\\WIMPOS;"
            "DATABASE=Pruebas;"
            "UID=sa;"
            "PWD=CIEV2011ev;"
        )
        conn = pyodbc.connect(connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        print(f"Connected to Pruebas: {version}")
        conn.close()
        return True
    except Exception as e:
        print(f"Connection to Pruebas failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing Portal DB connection...")
    test_portal_connection()
    print("\nTesting Editor DB connection...")
    test_editor_connection()