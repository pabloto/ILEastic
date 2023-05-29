**free
Ctl-Opt  DftActGrp(*no)ActGrp(*StgMdl)
  StgMdl(*SNGLVL)
  BndDir('AL400MNUV2')
  Thread(*Concurrent)
  Option(*NoUnRef :*SrcStmt :*NoDebugIo)
  DatFmt(*Iso) TimFmt(*Iso)
  Debug(*Constants)
  Expropts(*AlwBlankNum)
  AlwNull(*UsrCtl)
  DftName(TESTJWT)
  Text('Test jwt');
// ____________________________________________________________________________
/INCLUDE 'jwt/jwt_rsa/ujwtsrvpgm.rpgleinc'
Dcl-s ValidUntil Timestamp;
Dcl-s Jwt        Like(Utf8String_t);
Dcl-s Header     VarChar(100)  Ccsid(*utf8);
Dcl-s Payload    VarChar(1000) Ccsid(*utf8);
Dcl-s Rc         Int(10);

Header = '{"alg":"RS512","typ":"JWT"}';
Payload = '{"sub":"123","user":"PAOLOS","exp":30}';
Jwt = UJwtCreate(Header :Payload :ValidUntil);

Rc = UJwtVerify(Jwt);

snd-msg Jwt;

Return;