USE mysql;
-- CREATE USER 'test'@'localhost' IDENTIFIED BY 'zaphod';
GRANT ALL PRIVILEGES ON fpki.* TO 'test'@'localhost';
-- needed for mapserver
GRANT SUPER ON *.* TO test@localhost;
-- UPDATE user SET plugin='auth_socket' WHERE User='test';
FLUSH PRIVILEGES;
