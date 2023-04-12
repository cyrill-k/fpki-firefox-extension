USE mysql;
CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY 'zaphod';
GRANT ALL PRIVILEGES ON fpki.* TO 'test'@'%';
-- needed for mapserver
GRANT SUPER ON *.* TO 'test'@'%';
-- UPDATE user SET plugin='auth_socket' WHERE User='test';
FLUSH PRIVILEGES;
