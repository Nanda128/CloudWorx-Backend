CREATE TABLE
    IF NOT EXISTS user_login (
        id CHAR(36) NOT NULL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        auth_password TEXT NOT NULL,
        email VARCHAR(320) NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (username)
    );

CREATE TABLE
    IF NOT EXISTS user_kek (
        key_id CHAR(36) NOT NULL PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        iv_KEK TEXT NOT NULL,
        encrypted_KEK TEXT NOT NULL,
        assoc_data_KEK TEXT NOT NULL,
        salt TEXT NOT NULL,
        p int NOT NULL,
        m int NOT NULL,
        t int NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (user_id)
    );

CREATE TABLE
    IF NOT EXISTS files (
        file_id CHAR(36) NOT NULL PRIMARY KEY,
        file_name VARCHAR(255) NOT NULL UNIQUE,
        iv_file TEXT NOT NULL,
        encrypted_file LONGBLOB NOT NULL,
        assoc_data_file TEXT NOT NULL,
        created_by CHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_type VARCHAR(32) NULL,
        file_size INT NULL,
        FOREIGN KEY (created_by) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (created_by),
        INDEX (file_name)
    );

CREATE TABLE
    IF NOT EXISTS file_dek (
        key_id CHAR(36) NOT NULL PRIMARY KEY,
        file_id CHAR(36) NOT NULL,
        iv_dek TEXT NOT NULL,
        encrypted_dek TEXT NOT NULL,
        assoc_data_dek TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (file_id) ON DELETE CASCADE,
        INDEX (file_id)
    );

CREATE TABLE
    IF NOT EXISTS file_share (
        id CHAR(36) NOT NULL PRIMARY KEY,
        file_id CHAR(36) NOT NULL,
        shared_with CHAR(36) NOT NULL,
        encrypted_dek LONGBLOB NOT NULL,
        assoc_data_dek TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (file_id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (file_id),
        INDEX (shared_with)
    );