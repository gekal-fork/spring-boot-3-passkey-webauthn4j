# spring-security-fido2-login



## Create Project

[spring initializr](https://start.spring.io/)

- Project: Gradle
- Language: Kotlin
- Spring Boot: 3.3.0
- Java: 17
- Dependencies
  - Spring Web
  - Thymeleaf
  - Spring Security
  - Spring Data JPA
  - H2 Database



## Create Database

application.properties

```properties
spring.datasource.url=jdbc:h2:./test
spring.datasource.driver-class-name=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=
spring.h2.console.enabled=true
```



Connect to Database

- H2 Console

```http
http://localhost:8080/h2-console

Driver Class: org.h2.Driver
JDBC URL: jdbc:h2:./test
User Name: sa
Password: (empty)
```



Create Table

```sql
create table M_USER (
    INTERNAL_ID varchar(32) not null primary key,
    USER_ID varchar(32) not null unique,
    DISPLAY_NAME varchar(64) not null,
    PASSWORD varchar(128) not null
);

create table M_FIDO_CREDENTIAL_FOR_WEBAUTHN4J (
    ID int default 0 not null auto_increment primary key,
    CREDENTIAL_ID varbinary(1000) not null unique,
    USER_INTERNAL_ID varchar(32) not null,
    ATTESTED_CREDENTIAL_DATA varbinary(1000)
);

```



Insert Records

- user1, ユーザー1, password1
- user2, ユーザー2, password2
- user3, ユーザー3, password3 

```sql
INSERT INTO M_USER (INTERNAL_ID, USER_ID, DISPLAY_NAME, PASSWORD) VALUES
(
  '_USER1',
  'user1', 
  'ユーザー1',
  '{bcrypt}$2a$10$xeYLBfOQILT1XKYhofosg.a3I1Vg8vF6Kd4NXjfigyy/.N.7AwYU.'
),
(
  '_USER2',
  'user2', 
  'ユーザー2',
  '{bcrypt}$2a$10$142YrOgdho1EvrXhstuYMuD.6l5XrJt4yyJ6t6kcJLi7bHvDzpF3O'
),
(
  '_USER3',
  'user3', 
  'ユーザー3',
  '{bcrypt}$2a$10$WlijXJStltiGmakfhoRBQuMy2Xlw6EOtnbrMQRg65tlF0aU5y2.7i'
);
```



