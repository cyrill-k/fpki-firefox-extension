USE mysql;
-- CREATE USER 'test'@'localhost' IDENTIFIED BY 'zaphod';
GRANT ALL PRIVILEGES ON *.* TO 'test';
-- UPDATE user SET plugin='auth_socket' WHERE User='test';
FLUSH PRIVILEGES;
