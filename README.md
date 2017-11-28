# PHP-Login
A simple, lightweight login system built with PHP PDO and Bootstrap. As part of my 4th year Honors Degree in Software Development, Secure Application Development module I was tasked with creating a secure login system with PHP. I knew right away I was going to need to protect the system from things like sql injection, cross site scripting, session hijacking and brute force attacks. This project is my solution after researching various methods online. 

![alt text](https://i.gyazo.com/424cd3894d632b29133f95949ba03ffc.png)


# Database
```
CREATE DATABASE `login_system`;
```

Create a DB user account, give it permissions, and add it to the 'login_system' databse

```
CREATE TABLE `login_system`.`users` (
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(30) NOT NULL,
    `password` CHAR(128) NOT NULL
) ENGINE = InnoDB;
```
```
CREATE TABLE `login_system`.`login_attempts` (
    `user_id` INT(11) NOT NULL,
    `time` VARCHAR(30) NOT NULL
) ENGINE=InnoDB
```
```
INSERT INTO `login_system`.`users` VALUES(1, 'test', '$2y$10$IrzYJi10j3Jy/K6jzSLQtOLif1wEZqTRQoK3DcS3jdnFEhL4fWM4G');
```
You now have 
# Acknowledgments 
Thanks to the following for their help on this project

* [Bootsnipp](https://bootsnipp.com/snippets/featured/login-and-register-tabbed-form#comments) - The Bootstrap Theme
* [Wikihow](https://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL) - Parts of this tutorial were used
