CREATE TABLE
    IF NOT EXISTS user_login (
        id CHAR(36) NOT NULL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        auth_password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (username),
        INDEX (email)
    );

CREATE TABLE
    IF NOT EXISTS user_kek (
        key_id CHAR(36) NOT NULL PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        iv_KEK VARCHAR(255) NOT NULL,
        encrypted_KEK VARCHAR(255) NOT NULL,
        assoc_data_KEK VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (user_id)
    );

CREATE TABLE
    IF NOT EXISTS files (
        file_id CHAR(36) NOT NULL PRIMARY KEY,
        file_name VARCHAR(255) NOT NULL,
        iv_file VARCHAR(255) NOT NULL,
        encrypted_file LONGBLOB NOT NULL,
        assoc_data_file VARCHAR(255) NOT NULL,
        created_by CHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_type VARCHAR(32) NULL,
        file_size INT NULL,
        FOREIGN KEY (created_by) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (created_by)
    );

CREATE TABLE
    IF NOT EXISTS file_dek (
        key_id CHAR(36) NOT NULL PRIMARY KEY,
        file_id CHAR(36) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        iv_dek VARCHAR(255) NOT NULL,
        encrypted_dek VARCHAR(255) NOT NULL,
        assoc_data_dek VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (file_id) ON DELETE CASCADE,
        INDEX (file_id)
    );

CREATE TABLE
    IF NOT EXISTS file_share (
        id CHAR(36) NOT NULL PRIMARY KEY,
        file_id CHAR(36) NOT NULL,
        shared_with CHAR(36) NOT NULL,
        encrypted_dek VARCHAR(255) NOT NULL,
        iv_dek VARCHAR(255) NOT NULL,
        assoc_data_dek VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES files (file_id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with) REFERENCES user_login (id) ON DELETE CASCADE,
        INDEX (file_id),
        INDEX (shared_with)
    );