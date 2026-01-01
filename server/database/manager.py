"""
Database Manager for MessageU server.

This module handles all database operations including client registration,
message storage, and data retrieval using SQLite.
"""

import sqlite3
from datetime import datetime


class DatabaseManager:
    """
    Manages all database operations for the MessageU server.
    
    Handles client registration, message storage, and data retrieval
    using SQLite database.
    """
    
    def __init__(self, db_file):
        """
        Initializes the database connection and creates tables if they don't exist.
        
        Args:
            db_file: Path to the SQLite database file
            
        Raises:
            sqlite3.Error: If database cannot be initialized
        """
        self.db_file = db_file
        try:
            self._initialize_db()
        except sqlite3.Error as e:
            print(f"FATAL DB ERROR: Could not initialize database: {e}")
            raise  # Re-raise exception to stop the server if DB can't be created

    def _get_connection(self):
        """
        Internal method to get new DB connection.
        
        Returns:
            sqlite3.Connection: Database connection with timeout
        """
        # Timeout to avoid locking issues
        return sqlite3.connect(self.db_file, timeout=5)

    def _initialize_db(self):
        """
        Internal method to create the database tables if they don't exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    ID BLOB PRIMARY KEY,
                    UserName TEXT NOT NULL UNIQUE,
                    PublicKey BLOB NOT NULL,
                    LastSeen TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    ID INTEGER PRIMARY KEY AUTOINCREMENT,
                    ToClient BLOB NOT NULL,
                    FromClient BLOB NOT NULL,
                    Type INTEGER NOT NULL,
                    Content BLOB NOT NULL,
                    FOREIGN KEY(ToClient) REFERENCES clients(ID),
                    FOREIGN KEY(FromClient) REFERENCES clients(ID)
                )
            ''')
            conn.commit()
        print(f"Database initialized at {self.db_file}")

    def update_last_seen(self, client_uuid_bytes):
        """
        Updates LastSeen timestamp for client.
        
        Args:
            client_uuid_bytes: The client's UUID as bytes
        """
        try:
            with self._get_connection() as conn:
                conn.execute("UPDATE clients SET LastSeen = ? WHERE ID = ?",
                             (datetime.now().isoformat(), client_uuid_bytes))
        except sqlite3.Error as e:
            print(f"DB Error (update_last_seen): {e}")

    def register_client(self, uuid_bytes, username, public_key):
        """
        Registers new client - Returns True on success, False if username exists.
        
        Args:
            uuid_bytes: The client's UUID as bytes
            username: The client's username
            public_key: The client's public key as bytes
            
        Returns:
            bool: True if registration successful, False if username already exists
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO clients (ID, UserName, PublicKey, LastSeen) VALUES (?, ?, ?, ?)",
                    (uuid_bytes,
                     username,
                     public_key,
                     datetime.now().isoformat()))
            return True
        except sqlite3.IntegrityError:  # Username already exists
            return False
        # Catch any other DB error (e.g., disk full, locked)
        except sqlite3.Error as e:
            print(f"DB Error (register_client): {e}")
            return False

    def client_exists(self, uuid_bytes):
        """
        Checks if client exists by UUID.
        
        Args:
            uuid_bytes: The client's UUID as bytes
            
        Returns:
            bool: True if client exists, False otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM clients WHERE ID = ?", (uuid_bytes,))
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            print(f"DB Error (client_exists): {e}")
            return False  # Assume not exists if DB fails

    def get_client_name(self, uuid_bytes):
        """
        Return username by user's UUID.
        
        Args:
            uuid_bytes: The client's UUID as bytes
            
        Returns:
            str: The client's username, or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT UserName FROM clients WHERE ID = ?", (uuid_bytes,))
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.Error as e:
            print(f"DB Error (get_client_name): {e}")
            return None

    def get_public_key(self, uuid_bytes):
        """
        Return public key and username by user's UUID.
        
        Args:
            uuid_bytes: The client's UUID as bytes
            
        Returns:
            tuple: (public_key, username) or None if not found
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT PublicKey, UserName FROM clients WHERE ID = ?", (uuid_bytes,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            print(f"DB Error (get_public_key): {e}")
            return None

    def get_all_clients(self):
        """
        Returns list of pairs of information details (uuid_bytes, username) for all users.
        
        Returns:
            list: List of tuples (uuid_bytes, username) for all clients
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT ID, UserName FROM clients")
                return cursor.fetchall()
        except sqlite3.Error as e:
            print(f"DB Error (get_all_clients): {e}")
            return []  # Return empty list on failure

    def save_message(self, to_client, from_client, msg_type, content):
        """
        Saves a message to the database and returns the message ID.
        
        Args:
            to_client: Recipient's UUID as bytes
            from_client: Sender's UUID as bytes
            msg_type: Message type (integer)
            content: Message content as bytes
            
        Returns:
            int: The auto-generated message ID
            
        Raises:
            sqlite3.Error: If message cannot be saved
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "INSERT INTO messages (ToClient, FromClient, Type, Content) VALUES (?, ?, ?, ?)",
                    (to_client,
                     from_client,
                     msg_type,
                     content))
                return cursor.lastrowid  # Return the auto-generated message ID
        except sqlite3.Error as e:
            print(f"DB Error (save_message): {e}")
            raise e  # Re-raise to let the handler know it failed

    def get_waiting_messages(self, client_uuid_bytes):
        """
        Retrieves and deletes all waiting messages for a client.
        
        Args:
            client_uuid_bytes: The client's UUID as bytes
            
        Returns:
            list: List of tuples (ID, FromClient, Type, Content) for all waiting messages
        """
        messages = []
        try:
            with self._get_connection() as conn:
                # 'with conn:' creates an atomic transaction for both operations (select and delete)
                with conn:
                    # Get messages
                    cursor = conn.execute(
                        "SELECT ID, FromClient, Type, Content FROM messages WHERE ToClient = ?",
                        (client_uuid_bytes,))
                    messages = cursor.fetchall()
                    # Delete pulled messages
                    conn.execute(
                        "DELETE FROM messages WHERE ToClient = ?", (client_uuid_bytes,))
            return messages
        except sqlite3.Error as e:
            print(f"DB Error (get_waiting_messages): {e}")
            return []  # Return empty list on failure

    def delete_client(self, client_uuid_bytes):
        """
        Deletes a client and all their associated messages from the DB.
        
        Args:
            client_uuid_bytes: The client's UUID as bytes
            
        Returns:
            bool: True if client was deleted, False if client not found
        """
        try:
            with self._get_connection() as conn:
                with conn:  # Atomic transaction
                    # 1. Delete messages where user is sender OR receiver
                    conn.execute(
                        "DELETE FROM messages WHERE ToClient = ? OR FromClient = ?",
                        (client_uuid_bytes,
                         client_uuid_bytes))
                    # 2. Delete the client record
                    cursor = conn.execute(
                        "DELETE FROM clients WHERE ID = ?", (client_uuid_bytes,))

                    if cursor.rowcount > 0:
                        return True
                    else:
                        return False  # Client not found
        except sqlite3.Error as e:
            print(f"DB Error (delete_client): {e}")
            return False  # Indicate failure


