drop table if exists USERS;
drop table if exists AUTHORITIES;

CREATE TABLE USERS (
    ID BIGINT AUTO_INCREMENT,
    USERNAME VARCHAR(50) NOT NULL,
    PASSWORD VARCHAR(300) NOT NULL,
    ENABLED SMALLINT NOT NULL,
    PRIMARY KEY (USERNAME)
);

CREATE TABLE AUTHORITIES (
    ID BIGINT NOT NULL,
    USERNAME VARCHAR(50) NOT NULL,
    AUTHORITY VARCHAR(50) NOT NULL,
    FOREIGN KEY (USERNAME) REFERENCES USERS(USERNAME)
);

/*
INSERT INTO USERS (USERNAME, PASSWORD,ENABLED) VALUES
   ('admin', '{noop}1234',true),
   ('user1', '{noop}1234',true),
   ('user2', '{noop}1234',false);
*/

--테스트암호생성은 https://bcrypt-generator.com/ 에서 하면된다
INSERT INTO USERS (USERNAME, PASSWORD,ENABLED) VALUES
('admin', '$2y$12$de4XZ7DF49Ue.4hMJfUSouBy2Ui9/SBwfB5QeIdyhqD4u4636of96',true), --암호:1
('user1', '$2y$12$de4XZ7DF49Ue.4hMJfUSouBy2Ui9/SBwfB5QeIdyhqD4u4636of96',true), --암호:1
('user2', '$2y$12$de4XZ7DF49Ue.4hMJfUSouBy2Ui9/SBwfB5QeIdyhqD4u4636of96',false);--암호:1

--아래처럼 암호내 {bcrypt}는 삭제해야 정상인증처리묃..이거 어디 옵션이 있는건지 ...
--('user2', '{bcrypt}$2y$12$de4XZ7DF49Ue.4hMJfUSouBy2Ui9/SBwfB5QeIdyhqD4u4636of96',false);--암호:1


-- {noop}은 저장된 암호에 암호화가 적용되지 않았음을 나타낸다.
-- 스프링 보안은 위임을 사용해 사용할 인코딩 방법을 결정한다.
-- 값은 {bcrypt}, {scrypt}, {pdkdf2}, {sha256}이 될수 있다.
-- {sha256}은 주로 호한성을 이유로 존재하며 비보안으로 간주해야 한다.

/*
 ('admin@books.io', '{noop}secret',true),
   ('marten@books.io', '{noop}user',true),
   ('jdoe@books.net', '{noop}user',false);
*/


INSERT INTO AUTHORITIES (ID, USERNAME, AUTHORITY) VALUES
   (1,'admin', 'ADMIN'),
   (1,'admin', 'USER'),
   (2,'user1', 'USER'),
   (3,'user2', 'USER');