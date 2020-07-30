CREATE TABLE `cert_domainname` (
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Auto inc keynumber',
	`cert_id` INT UNSIGNED NOT NULL COMMENT 'The link to the certificate table, to wich certificate this uri is associated with.',
	`dn` VARCHAR(250) NOT NULL COMMENT 'The domain name as a verified DNS name',
	`ca_primary` ENUM('Y','N') NOT NULL DEFAULT 'N' COMMENT 'Primary used as certificate CA',
	PRIMARY KEY (`id`)
)
COLLATE='utf8mb4_swedish_ci';

CREATE TABLE `certificate` (
	`id` INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'Auto inc keynumber',
	`fullchain` TEXT NOT NULL COMMENT 'The full chain certificate',
	`privkey` TEXT NOT NULL COMMENT 'The private key for the certificate',
	`forward` VARCHAR(250) NOT NULL DEFAULT '127.0.0.1:80' COMMENT 'Forward IP:Port to the backend server HTTP',
	`active` ENUM('Y','N') NOT NULL DEFAULT 'N' COMMENT 'Is this cert active?',
	PRIMARY KEY (`id`)
)
COLLATE='utf8mb4_swedish_ci';
