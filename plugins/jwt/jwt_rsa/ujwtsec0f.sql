Create or Replace Table Al400sys/Ujwtsec0f (
      Dataoracreazione for column DataOraCrt Timestamp Not Null With Default Current Timestamp,
      CodiceCliente for column codcli     Varchar(100) Not Null Ccsid 1208,
      Secretkey                           Varchar(100) default null Ccsid 1208,
      Header                              Varchar(100) Not Null Ccsid 1208,
      Payload                             Varchar(1000) Not Null Ccsid 1208,
      Dataoraexpire for Column DataOraExp Timestamp Default '9999-12-31-00.00.00.000000',
      Isvalid                             Char(1) not null check (isValid  in ('Y', 'N')),
      jwt                                 Varchar(1000) default null CCsid 1208,
      keytype                             Char(5) default null ccsid 1208,
      PrivateKey                          Varchar(2400) default null ccsid 65535,
      PublicKey                           Varchar(512) default null ccsid 65535,
      Primary key (CodiceCliente, IsValid, Payload))
  Rcdfmt Ujwtsec;

Label on table Al400Sys/UJwtSec0f is 'JWT - Archivio secret key';

Label on column Al400sys/UJwtSec0f (
  DataoraCreazione  is 'DataOra             Jwt',
  CodiceCliente     is 'Codice              Cliente',
  SecretKey         is 'SecretKey',
  header            is 'Header',
  Payload           is 'Payload',
  Dataoraexpire     is 'DataOra             Scadenza            SecretKey',
  IsValid           is 'Flag                Y=Valido            N=Scaduto',
  jwt               is 'Json                Web                 Token',
  keytype           is 'keytype             HS256, HS382, RS256,RS382ES256,ES382',
  PrivateKey        is 'Private             key',
  PublicKey         is 'Public              key'
  );


Label on column Al400sys/UJwtSec0f (
  DataoraCreazione Text is 'DataOra Jwt',
  CodiceCliente    Text is 'Codice Cliente',
  SecretKey        Text is 'SecretKey',
  header           Text is 'Header',
  Payload          Text is 'Payload',
  Dataoraexpire    Text is 'DataOra Scadenza SecretKey',
  IsValid          Text is 'Flag Y=Valido N=Scaduto',
  jwt              Text is 'Json Web Token',
  keytype        Text is 'keytype HS256, HS382, RS256,RS382ES256,ES382',
  PrivateKey       Text is 'Private key',
  PublicKey        Text is 'Public key');
