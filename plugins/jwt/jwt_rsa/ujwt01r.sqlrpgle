**free
Ctl-Opt
  Expropts(*AlwBlankNum)
  Option(*NoUnRef :*SrcStmt :*NoDebugIo)
  DatFmt(*Iso) TimFmt(*Iso)
  Debug(*constants)
  AlwNull(*UsrCtl)
  DftName(UJWT01R)
  NoMain
  Text('JWT - JSon web Token with RSA');
// ____________________________________________________________________________
/INCLUDE 'jwt/jwt_rsa/ujwtsrvpgm.rpgleinc'
// ____________________________________________________________________________
///
// UJwtCreate
// Creazione Jwt
///
dcl-proc UJwtCreate Export;
  dcl-pi UJwtCreate likeds(DsJwt_t);
    Header          varchar(100)  const ccsid(*utf8);
    Payload         like(Utf8String_t) const;
    ValidUntil      timeStamp;
  end-pi UJwtCreate;

  dcl-ds DsJwt    likeds(DsJwt_t) inz;

  dcl-s HashAlg   varchar(20);
  dcl-s Idx       int(10);
  // ____________________________________________________________________________

  exec sql
    Values (json_value(:Header, '$.alg'  returning varchar(20)))
      into :HashAlg;
  if (SqlState <> '00000');
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  Idx = %LookUp(HashAlg :DsHash.Arr(*).AlgD);

  if (Idx = 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  select;

      // Jwt sincrono con chiave segreta HMAC
    when (DsHash.Arr(Idx).AlgType = HMAC);
      DsJwt = UJwtHMAC(Header
                      :Payload
                      :ValidUntil
                      :%Int(DsHash.Arr(Idx).SigningHashAlgorithm)
                      :DsHash.Arr(Idx).AlgD);

      // Jwt Asincrono con chiave segreta EDCSA
    when (DsHash.Arr(Idx).AlgType = EDCSA);
      DsJwt = UJwtECDSA(Header
                      :Payload
                      :%Int(DsHash.Arr(Idx).SigningHashAlgorithm)
                      :DsHash.Arr(Idx).AlgD);

      // Jwt Asincrono con chiave segreta RSA
    when (DsHash.Arr(Idx).AlgType = RSA);
      DsJwt = UJwtRSA(Header
                      :Payload
                      :%Int(DsHash.Arr(Idx).SigningHashAlgorithm)
                      :DsHash.Arr(Idx).AlgD);


  endsl;

  return DsJwt;

end-proc UJwtCreate;
// ____________________________________________________________________________
///
// UJwtHMAC
// Creazione Jwt HMAC
// Jwt sincrono con shared key
///
dcl-proc UJwtHMAC;
  dcl-pi UJwtHMAC  likeds(DsJwt_t);
    Header                    varchar(100)  const ccsid(*utf8);
    Payload                   varchar(1000) const ccsid(*utf8);
    ValidUntil                timestamp;
    SigningHashAlgorithm      int(10) const;
    AlgorithmType             char(5) const;
  end-pi UJwtHMAC;
  dcl-ds DsEnc likeds(DsEnc_t) inz;
  dcl-ds DsJwt likeds(DsJwt_t) inz;

  dcl-s SecretKey       varchar(100) ccsid(*utf8);
  dcl-s WorkString      like(Utf8String_t);
  dcl-s JwtB64Temp      like(Utf8String_t);
  dcl-s CodiceCliente   varchar(100);

  // ____________________________________________________________________________

  exec sql
    Values (json_value(:Payload, '$.user'  returning varchar(100)))
      into :CodiceCliente;
  if (SqlState <> '00000');
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  exec sql
    Select SecretKey into :SecretKey
      from UJwtSec0f
      where IsValid = 'Y' and CodiceCliente = :CodiceCliente;
  if (SqlState = '02000');
    exec sql
      Select SecretKey into :SecretKey
        from final table (
          Insert into UJwtSec0f (CodiceCliente, SecretKey, IsValid,
                   Payload, Header)
          Values(:CodiceCliente,
                  '01234567890123456789012345678901',
                   'Y', :Payload, :Header));
  endif;
  if (SqlState <> '00000');
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  DsEnc = UJwtEncodeHeaderPassword(Header:Payload);
  if (DsEnc.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  WorkString = DsEnc.StringEncoded;

  JwtB64Temp = UJwtCalculateHMac(WorkString :SecretKey
      :SigningHashAlgorithm);

  JwtB64Temp = UJwtEncodeBase64(JwtB64Temp :%len(JwtB64Temp) :*on);

  WorkString += PUNTO + JwtB64Temp;
  DsJwt.Jwt = WorkString;

  exec sql
    Update UJwtSec0f
      set jwt = :WorkString
      where IsValid = 'Y' and CodiceCliente = :CodiceCliente and Payload = :Payload;

  return DsJwt;

end-proc UJwtHMAC;
// ____________________________________________________________________________
///
// UJwtECDSA
// Creazione jwt ascinrono con chiave ECSDA SHA256
///
// ____________________________________________________________________________
dcl-proc UJwtECDSA;
  dcl-pi UJwtECDSA likeds(DsJwt_t);
    Header                    varchar(100)  ccsid(*utf8) const;
    Payload                   like(Utf8String_t) const;
    SigningHashAlgorithm      int(10) const;
    AlgorithmType             char(5) const;
  end-pi UJwtECDSA;

  dcl-ds DsSignature    likeds(DsSignature_t) inz;
  dcl-ds DsEnc          likeds(DsEnc_t) inz;
  dcl-ds DsJwt          likeds(DsJwt_t) inz;

  dcl-s WorkString      like(Utf8String_t);
  dcl-s JwtB64Temp      like(Utf8String_t);

  // ____________________________________________________________________________

  DsEnc = UJwtEncodeHeaderPassword(Header:Payload);
  if (DsEnc.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  DsSignature = UJwtCalculateSignature(DsEnc.StringEncoded
                                        :SigningHashAlgorithm
                                        :Header
                                        :Payload
                                        :AlgorithmType);
  if (DsSignature.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  WorkString = DsEnc.StringEncoded;

  DsEnc = UJwtEncodeBase64(DsSignature.Signature :%len(JwtB64Temp) :*on);
  if (DsEnc.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  DsJwt = WorkString + PUNTO + JwtB64Temp;

  return DsJwt;

end-proc UJwtECDSA;
// ____________________________________________________________________________
///
// UJwtRSA
// Creazione jwt ascinrono con chiave RSA
///
// ____________________________________________________________________________
dcl-proc UJwtRSA;
  dcl-pi UJwtRSA likeds(DsJwt_t);
    Header                  varchar(100)  ccsid(*utf8) const;
    Payload                 like(Utf8String_t) const;
    SigningHashAlgorithm    int(10) const;
    AlgorithmType             char(5);
  end-pi UJwtRSA;
  dcl-ds DsSignature    likeds(DsSignature_t) inz;
  dcl-ds DsEnc          likeds(DsEnc_t) inz;
  dcl-ds DsJwt          likeds(DsJwt_t) inz;

  dcl-s WorkString      like(Utf8String_t);
  // ____________________________________________________________________________

  DsEnc = UJwtEncodeHeaderPassword(Header:Payload);
  if (DsEnc.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  DsSignature = UJwtCalculateSignature(DsEnc.StringEncoded
                                      :SigningHashAlgorithm
                                      :Header
                                      :Payload
                                      :AlgorithmType);
  if (DsSignature.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  WorkString = DsEnc.StringEncoded;

  DsEnc = UJwtEncodeBase64(DsSignature.Signature
                          :DsSignature.SignatureLen
                          :*on);
  if (DsEnc.Rc < 0);
    DsJwt.Rc = -1;
    return DsJwt;
  endif;

  DsJwt.Jwt = WorkString + PUNTO + DsEnc.StringEncoded;

  return DsJwt;

end-proc UJwtRSA;
// ____________________________________________________________________________
///
// UJwtCalculateHMac
// Calculate HMAC
///
// ____________________________________________________________________________
dcl-proc UJwtCalculateHMac;
  dcl-pi UJwtCalculateHMac varchar(32) ccsid(*utf8);
    WorkString              like(Utf8String_t) const;
    SecretKey               varchar(100) ccsid(*utf8);
    SigningHashAlgorithm    int(10) const;
  end-pi UJwtCalculateHMac;
  dcl-s WorkSha        char(32);
  dcl-s WorkShaUtf8    char(32) based(PtrWork) ccsid(*utf8);
  dcl-ds My_Key likeds(My_Key_t) inz;

  // ____________________________________________________________________________
  My_Key.Type   = SigningHashAlgorithm;
  My_Key.Value  = SecretKey;
  My_Key.Len    = %len(SecretKey);
  My_Key.Fmt    = '0';

  Qc3CalculateHMAC(WorkString
                  :%len(WorkString)
                  :DATA0100_FMT
                  :SigningHashAlgorithm
                  :ALGD0500_FMT
                  :My_Key
                  :KEYD0200_FMT
                  :'0'
                  :*Blanks
                  :WorkSha
                  :ApiError);
  if (ApiError.BytAvl > 0);
    return 'Errore generazione jwt';
  endif;

  PtrWork = %Addr(WorkSha);

  return %trim(WorkShaUtf8);

end-proc UJwtCalculateHMac;
// ____________________________________________________________________________
///
// UJwtEcdsaKey
// Generazione ECDSA key pair
///
dcl-proc UJwtEcdsaKey Export;
  dcl-pi UJwtEcdsaKey likeds(DsKey_t);
    SigningHashAlgorithm        Int(10);
  end-pi UJwtEcdsaKey;

  dcl-s AlgorithmContextToken char(8);
  dcl-ds DsKey          likeds(DsKey_t) inz;
  // ____________________________________________________________________________

  AlgorithmContextToken = UJwtCrtAlgCtx(SigningHashAlgorithm :ES256);

  reset DsKey;

  Qc3GenECCKeyPair(SECP256R1
                  :%len(SECP256R1)
                  :ECC
                  :BERSTRING
                  :KEYFORMCLEAR
                  :''
                  :''
                  :SOFTWARECSP
                  :''
                  :DsKey.Private
                  :%len(DsKey.Private)
                  :DsKey.PrivateKeyLength
                  :DsKey.Public
                  :%len(DsKey.Public)
                  :DsKey.PublicKeyLength
                  :ApiError);

  if (ApiError.BytAvl > 0);
    reset DsKey;
    DsKey.Rc = -1;
  endif;

  return DsKey;

end-proc UJwtEcdsaKey;
// ____________________________________________________________________________
///
// UJwtCalculateSignature
// Calcola firma
///
dcl-proc UJwtCalculateSignature;
  dcl-pi UJwtCalculateSignature likeds(DsSignature_t);
    WorkString              like(Utf8String_t);
    SigningHashAlgorithm    int(10) const;
    Header                  varchar(100)  ccsid(*utf8) const;
    Payload                 like(Utf8String_t) const;
    AlgorithmType           char(5) const;
  end-pi UJwtCalculateSignature;

  dcl-ds KeyD0200   likeds(KeyD0200_t) Inz;
  dcl-ds DsKey        likeds(DsKey_t) inz;
  dcl-ds AlgD0400   likeds(AlgD0400_t) inz;
  dcl-ds DsSignature  likeds(DsSignature_t) inz;

  dcl-s WorkStringHex     varchar(2400) ccsid(*hex);

  // ____________________________________________________________________________

  DsKey = UJwtGetKey(Header
                    :Payload
                    :AlgorithmType
                    :'Y'
                    :'/home/paolos/jwt_public'
                    :'/home/paolos/jwt_private');

  if ( DsKey.Rc < 0);
    DsSignature.Rc = -1;
    return DsSignature;
  endif;

  KeyD0200.Reserved     = *allx'00';
  KeyD0200.KeyType      = RSAPRIVATE;
  KeyD0200.KeyFormat    = BERSTRING;
  KeyD0200.KeyString    = DsKey.Private;
  KeyD0200.KeyStringLen = DsKey.PrivateKeyLength;

  AlgD0400 = *allx'00';
  AlgD0400.PublicKeyAlgorithm = RSAPUBLICKEYALGORITHM;
  AlgD0400.PKABlockFormat = PKCS1;
  AlgD0400.SigningHashAlgorithm = SigningHashAlgorithm;

  WorkStringHex = WorkString;

  Qc3CalculateSignature(WorkStringHex
                        :%len(WorkStringHex)
                        :DATA0100_FMT
                        :AlgD0400
                        :ALGD0400_FMT
                        :KeyD0200
                        :KEYD0200_FMT
                        :SOFTWARECSP
                        :''
                        :DsSignature.Signature
                        :%Size(DsSignature.Signature)
                        :DsSignature.SignatureLen
                        :ApiError);

  if (ApiError.BytAvl > 0);
    DsSignature.Rc = -1;
  endif;

  return DsSignature;

end-proc UJwtCalculateSignature;
// ____________________________________________________________________________
///
// UJwtGetKey
// Get key for user
///
dcl-proc UJwtGetKey;
  dcl-pi UJwtGetKey likeds(DsKey_t);
    Header              varchar(100) ccsid(*utf8) const;
    Payload             like(Utf8String_t) const;
    AlgorithmType       char(5) const;
    CreateKey           char(1) const options(*omit);
    // public certificate location without extension
    CertStmfpub         varchar(640) const options(*omit);
    // Private certificate location without extension
    CertStmfprv         varchar(640) const options(*omit);
  end-pi UJwtGetKey;

  dcl-ds DsKey likeds(DsKey_t) Inz;
  dcl-s CodiceCliente varchar(100);
  // ____________________________________________________________________________
  reset CodiceCliente;

  exec sql
    Values (json_value(:Payload, '$.user'  returning varchar(100)))
      into :CodiceCliente;
  if (SqlState <> '00000');
    reset DsKey;
    DsKey.Rc = -1;
  endif;

  exec sql
    Select 0, PrivateKey, Length(PrivateKey), PublicKey, Length(PublicKey)
      into :DsKey
      from UJwtSec0f
      where CodiceCliente = :CodiceCliente
            and IsValid = 'Y' and KeyType = :AlgorithmType;

  if (SqlState = '02000' and CreateKey = 'Y');
    DsKey = UJwtPkaKey(AlgorithmType
                        :CertStmfpub
                        :CertStmfprv);
    if (DsKey.Rc = -1);
      return DsKey;
    endif;

    exec sql
      Insert into UJwtSec0f (CodiceCliente, IsValid, Payload,
                            Header, PrivateKey, PublicKey, KeyType)
        Values(:CodiceCliente,'Y', :Payload, :Header, trim(:DsKey.Private),
                trim(:DsKey.Public), :AlgorithmType);
    if (SqlState <> '00000');
      DsKey.Rc = -1;
      return DsKey;
    endif;

  endif;

  if (SqlState <> '00000');
    reset Dskey;
    DsKey.Rc = -1;
    return DsKey;
  endif;

  return DsKey;

end-proc UJwtGetKey;
// ____________________________________________________________________________
///
// UJwtPkaKey
// Generazione PKA key pair
///
dcl-proc UJwtPkaKey export;
  dcl-pi UJwtPkaKey likeds(DsKey_t);
    AlgorithmType       char(5) const;
    // public certificate location without extension
    CertStmfpub         varchar(640) const;
    // Private certificate location without extension
    CertStmfprv         varchar(640) const;
  end-pi UJwtPkaKey;

  dcl-ds DsKey likeds(DsKey_t) Inz;

  // ____________________________________________________________________________

  Qc3GenPKAKeyPair(KEYTYPERSA
                  :KEYSIZE2048
                  :PUBLICKEYEXP65537
                  :BERSTRING
                  :KEYFORMCLEAR
                  :''
                  :''
                  :SOFTWARECSP
                  :' '
                  :DsKey.Private
                  :%len(DsKey.Private)
                  :DsKey.PrivateKeyLength
                  :DsKey.Public
                  :%len(DsKey.Public)
                  :DsKey.PublicKeyLength
                  :ApiError);
  if (ApiError.BytAvl > 0);
    DsKey.Rc = -1;
    return DsKey;
  endif;

  UJwtWriteCertStmf(%subst(DsKey.Private :1 :DsKey.PrivateKeyLength)
                    :DsKey.PrivateKeyLength
                    :CertStmfprv
                    :BEGINCERTPRIVATE
                    :ENDCERTPRIVATE
                    :AlgorithmType);


  UJwtWriteCertStmf(%subst(DsKey.Public :1 :DsKey.PublicKeyLength)
                    :DsKey.PublicKeyLength
                    :CertStmfpub
                    :BEGINCERTPUBLIC
                    :ENDCERTPUBLIC
                    :AlgorithmType);

  return DsKey;

end-proc UJwtPkaKey;
// ____________________________________________________________________________
///
// UJwtWriteCertStmf
// Decrypt chiave
///
dcl-proc UJwtWriteCertStmf;
  dcl-pi UJwtWriteCertStmf;
    BinaryField         varchar(2400) const ccsid(*hex);
    BinaryLength        int(10) const;
    // certificate location without extension
    CertStmf            varchar(640) const;
    Header              varchar(64) const;
    Footer              varchar(64) const;
    AlgorithmType       char(5) const;
  end-pi UJwtWriteCertStmf;

  dcl-s StmfFile        sqltype(clob_file) ccsid(*utf8);
  dcl-s StmfFile_blob   sqltype(blob_file) ccsid(*hex);
  dcl-s KeyUtf8         like(Utf8String_t);
  dcl-s PosEnd          int(10);
  dcl-s PosStart        int(10);
  dcl-s KeyClob         sqltype(clob :100000) ccsid(*utf8);

  // ____________________________________________________________________________

  StmfFile_blob_Name = CertStmf + '_' + %trim(AlgorithmType) + '.der';
  StmfFile_blob_NL   = %len(%trim(StmfFile_blob_Name));
  StmfFile_blob_FO   = SQFOVR; // OverWrite

  exec sql
    Set :StmfFile_blob = :BinaryField;

  StmfFile_Name = CertStmf + '_' + %trim(AlgorithmType) + '.pem';
  StmfFile_NL   = %len(%trim(StmfFile_Name));
  StmfFile_FO   = SQFOVR; // OverWrite

  PosStart = 1;
  KeyClob_data = Header + CRLF;
  KeyUtf8 = UJwtEncodeBase64(BinaryField :BinaryLength :*off);

  dow (1=1);

    if ((%len(KeyUtf8) - PosStart) > PEMRECORDLENGTH);
      PosEnd = PEMRECORDLENGTH;
    Else;
      PosEnd = (%len(KeyUtf8) - PosStart) +1;
    endif;

    KeyClob_data = %trim(KeyClob_data) + %subst(KeyUtf8 :PosStart :PosEnd) + CRLF;

    if ((PosEnd < PEMRECORDLENGTH) or ((%len(KeyUtf8) - PosStart) = 0));
      Leave;
    endif;
    PosStart = PosStart + PEMRECORDLENGTH;

  enddo;

  KeyClob_data = %trim(KeyClob_data) + Footer + CRLF;
  KeyClob_len = %len(%trim(KeyClob_data));

  exec sql
    Set :StmfFile = :KeyClob;

  Return;

end-proc UJwtWriteCertStmf;
// ____________________________________________________________________________
///
// UJwtDecryptData
// Decrypt chiave
///
dcl-proc UJwtDecryptData export;
  dcl-pi UJwtDecryptData like(OutputkeyVar_t);
    EncryptedData                   like(Utf8String_t);
    AlgorithmDescription            char(9) const;
    AlgorithmDescriptionFormatName  char(8) const;
    KeyD0200                      likeds(KeyD0200_t);
  end-pi UJwtDecryptData;
  dcl-s ClearData                   char(5000);
  dcl-s LengthOfClearDataReturned   int(10);

  Qc3DecryptData(EncryptedData
                 :%len(EncryptedData)
                 :AlgorithmDescription
                 :AlgorithmDescriptionFormatName
                 :KeyD0200
                 :KEYD0200_FMT
                 :SOFTWARECSP
                 :''
                 :ClearData
                 :%len(ClearData)
                 :LengthOfClearDataReturned
                 :ApiError);

  return ClearData;

end-proc UJwtDecryptData;
// ____________________________________________________________________________
///
// UJwtExtractkey
// Extract key
///
dcl-proc UJwtExtractkey Export;
  dcl-pi UJwtExtractkey like(OutputkeyVar_t);
    Dskey likeds(DsKey_t);
  end-pi UJwtExtractkey;

  dcl-s Outputkey           char(5000);
  dcl-s OutputkeyVar        like(OutputkeyVar_t);
  dcl-s OutputkeyReturned   int(10);

  // ____________________________________________________________________________

  Qc3ExtractPublicKey(Dskey.Public
                      :Dskey.PublicKeyLength
                      :BERSTRING
                      :KEYFORMCLEAR
                      :''
                      :''
                      :Outputkey
                      :%len(Outputkey)
                      :OutputkeyReturned
                      :ApiError);

  OutputkeyVar = %trim(Outputkey);

  return OutputkeyVar;

end-proc UJwtExtractkey;
// ____________________________________________________________________________
///
// UJwtExportKey
// Esporta key in PKCS#8
///
dcl-proc UJwtExportkey Export;
  dcl-pi UJwtExportkey like(OutputkeyVar_t);
    Dskey       likeds(DsKey_t);
  end-pi UJwtExportkey;

  dcl-s OutputkeyVar        like(OutputkeyVar_t);
  dcl-s Outputkey           char(5000);
  dcl-s OutputkeyReturned   int(10);

  // ____________________________________________________________________________

  // Qc3ExportKey(DskeyExt.Public
  //             :DskeyExt.PublicKeyLength
  //             :BERSTRING
  //             :KEYFORMCLEAR
  //             :''
  //             :''
  //             :Outputkey
  //             :%len(Outputkey)
  //             :OutputkeyReturned
  //             :ApiError);

  OutputkeyVar = %trim(Outputkey);

  return OutputkeyVar;

end-proc UJwtExportkey;
// ____________________________________________________________________________
///
// UJwtCrtKeyCtx
// Crea Key Context
///
dcl-proc UJwtCrtKeyCtx Export;
  dcl-pi UJwtCrtKeyCtx char(8);
    KeyString         varchar(4096) const;
  end-pi UJwtCrtKeyCtx;

  dcl-s KeyContextToken char(8);

  Qc3CreateKeyContext(KeyString
                     :%len(KeyString)
                     :PEMCERTIFICATE
                     :ECCPRIVATE
                     :KEYFORMCLEAR
                     :*omit
                     :*omit
                     :KeyContextToken
                     :ApiError);

  return KeyContextToken;

end-proc UJwtCrtKeyCtx;
// ____________________________________________________________________________
///
// UJwtCrtAlgCtx
// Crea Algoritmh Context
///
dcl-proc UJwtCrtAlgCtx Export;
  dcl-pi UJwtCrtAlgCtx char(8);
    SigningHashAlgorithm    int(10) const;
    Algorithm               char(5) const;
  end-pi UJwtCrtAlgCtx;

  dcl-ds AlgD0400           likeds(AlgD0400_t) inz;
  dcl-ds AlgD0600           likeds(AlgD0600_t) inz;
  dcl-s AlgorithmContextToken char(8);
  dcl-s AlgorithmDescrition   char(100);
  dcl-s Domain char(100);
  dcl-s FormatName char(8);
  // ____________________________________________________________________________

  if (Algorithm = ES256);
    AlgD0600.EllipticCurvePublicKeyAlgorithm = ELLIPTICCURVEPUBLICKEYALGORITHM;
    AlgD0600.SigningHashAlgorithm = SigningHashAlgorithm;
    Domain = SECP256R1;
    AlgD0600.Reserved = *allx'00';
    AlgD0600.DomainParameters = '';
    AlgD0600.DomainParametersLength = 0;
    FormatName = ALGD0600_FMT;
    AlgorithmDescrition = AlgD0600;
  elseif (Algorithm = RS256);
    AlgD0400.PublicKeyAlgorithm = RSAPUBLICKEYALGORITHM;
    AlgD0400.PKABlockFormat = PKCS1;
    AlgD0400.SigningHashAlgorithm = SigningHashAlgorithm;
    AlgD0400.Reserved = *allx'00';
    AlgorithmDescrition = AlgD0400;
    FormatName = ALGD0400_FMT;
  endif;

  Qc3CreateAlgorithmContext(AlgorithmDescrition
                            :FormatName
                            :AlgorithmContextToken
                            :ApiError);

  return AlgorithmContextToken;

end-proc UJwtCrtAlgCtx;
// ____________________________________________________________________________
///
// UJwtCheckUserIbmi
// Controllo user and password IBM i
///
dcl-proc UJwtCheckUserIbmi Export;
  dcl-pi UJwtCheckUserIbmi  likeds(DsCheckUser_t);
    User            char(10) const;
    Password        char(128) const;
  end-pi UJwtCheckUserIbmi;

  dcl-ds DsCheckUser likeds(DsCheckUser_t);
  dcl-s ProfileHandle char(12);
  // ____________________________________________________________________________

  GetProfileHandle(User
                  :Password
                  :ProfileHandle
                  :ApiError
                  :%len(Password)
                  :0);

  if (ApiError.BytAvl > 0);
    DsCheckUser.Rc = -1;
    DsCheckUser.ErrorMessage = ApiError.MsgDta;
  endif;

  return DsCheckUser;

end-proc UJwtCheckUserIbmi;
// ____________________________________________________________________________
///
// UJwtEncodeHeaderPassword
// Encrypt Header e Payload
///
dcl-proc UJwtEncodeHeaderPassword;
  dcl-pi UJwtEncodeHeaderPassword likeds(DsEnc_t);
    Header              varchar(100) ccsid(*utf8) const;
    Payload             like(Utf8String_t) const;
  end-pi UJwtEncodeHeaderPassword;
  dcl-ds DsEnc      likeds(DsEnc_t) inz;
  dcl-s WorkString  like(Utf8String_t);
  // ____________________________________________________________________________

  DsEnc = UJwtEncodeBase64(Header :%len(Header) :*on);
  if (DsEnc.Rc < 0);
    return DsEnc;
  endif;
  WorkString = DsEnc.StringEncoded + PUNTO;

  DsEnc = UJwtEncodeBase64(Payload :%len(Payload) :*on);
  if (DsEnc.Rc < 0);
    return DsEnc;
  endif;
  DsEnc.StringEncoded = WorkString + DsEnc.StringEncoded;

  return DsEnc;

end-proc UJwtEncodeHeaderPassword;

// ____________________________________________________________________________
///
// UJwtEncodeBase64
// Encode base64
///
dcl-proc UJwtEncodeBase64 export;
  dcl-pi UJwtEncodeBase64 likeds(DsEnc_t);
    StringToEncode    char(2400) ccsid(*hex) const;
    StringToEncodeLen int(10) const;
    B64Url            ind const;
  end-pi UJwtEncodeBase64;

  dcl-ds DsEnc likeds(DsEnc_t) inz;

  dcl-s StringToEncodedHex  varchar(2400) ccsid(*hex);
  dcl-s FROMB64             char(2) inz('+/') ccsid(*utf8);
  dcl-s TOB64               char(2) inz('-_') ccsid(*utf8);
  dcl-s UGUALE              char(1) inz('=') ccsid(*utf8);
  // ____________________________________________________________________________

  reset DsEnc.StringEncoded;
  StringToEncodedHex = %subSt(StringToEncode :1 :StringToEncodeLen);

  exec sql
    Values Base64_Encode(:StringToEncodedHex) into :DsEnc.StringEncoded;
  if (SqlState <> '00000');
    reset DsEnc;
    DsEnc.Rc = -1;
    return DsEnc;
  endif;

  if (B64Url);
    // Trasformo in base64url dove anzichè i caratteri +/ ci sono '-_'
    DsEnc.StringEncoded = %trimr(%xlate(FROMB64 : TOB64 : DsEnc.StringEncoded) :UGUALE);
  endif;

  return DsEnc;

end-proc UJwtEncodeBase64;
// ____________________________________________________________________________
///
// UJwtDecodeBase64
// Decode base64
///
dcl-proc UJwtDecodeBase64 export;
  dcl-pi UJwtDecodeBase64 likeds(DsDec_t);
    StringToDecode    like(Utf8String_t) const;
    StringToDecodeLen int(10) const;
    B64Url            ind const;
  end-pi UJwtDecodeBase64;

  dcl-ds DsDec likeds(DsDec_t);

  dcl-s StringToDecodedWork like(Utf8String_t);
  dcl-s StringDecodedHex    varchar(2400) ccsid(*hex);
  dcl-s FROMB64             char(2) inz('+/') ccsid(*utf8);
  dcl-s TOB64               char(2) inz('-_') ccsid(*utf8);
  dcl-s UGUALEFILL          char(2) inz('==') ccsid(*utf8);
  dcl-s Remainder           int(10);
  // ____________________________________________________________________________

  reset StringDecodedHex;

  if (B64Url);
    // Trasformo in base64url dove anzichè i caratteri +/ ci sono '-_'
    StringToDecodedWork = %xlate( TOB64 :FROMB64 :StringToDecode);
  endif;

  Remainder = %len(StringToDecodedWork);
  Remainder = (%rem(%len(StringToDecodedWork) :4));

  select;
      // when (Remainder = 1);
      //   StringToDecodedWork = StringToDecodedWork + UGUALEFILL;
    when (Remainder = 2);
      StringToDecodedWork = StringToDecodedWork + UGUALEFILL;
    when (Remainder = 3);
      StringToDecodedWork = StringToDecodedWork + %subst(UGUALEFILL :1 :1);
  endsl;

  exec sql
    Values Base64_Decode(:StringToDecodedWork) into :StringDecodedHex;
  if (SqlState <> '00000');
    DsDec.Rc = -1;
    return DsDec;
  endif;

  DsDec.StringDecodedHex = StringDecodedHex;


  return DsDec;

end-proc UJwtDecodeBase64;

// ____________________________________________________________________________
///
// UJwtVerify
// Verifica validità jwt
///
// ____________________________________________________________________________
Dcl-Proc UJwtVerify export;
  Dcl-Pi UJwtVerify int(10);
    Jwt        like(Utf8String_t) const;
  End-Pi UJwtVerify;

  dcl-ds KeyD0200       likeds(KeyD0200_t) inz;
  dcl-ds AlgD0400       likeds(AlgD0400_t) inz;
  dcl-ds DsKey          likeds(DsKey_t) inz;
  dcl-ds DsDec          likeds(DsDec_t) inz;

  dcl-s JwtArr          like(Utf8String_t) dim(3);
  dcl-s Signature       char(1000) ccsid(*hex);
  dcl-s SignatureLen    int(10);
  dcl-s Header          varchar(100) ccsid(*utf8);
  dcl-s Payload         like(Utf8String_t);
  dcl-s WorkString      like(Utf8String_t);
  dcl-s CodiceCliente   varchar(100) ccsid(*utf8);
  dcl-s HashAlg         varchar(20);
  dcl-s Idx             int(10);
  // ____________________________________________________________________________

  JwtArr = %split(Jwt :PUNTO);

  DsDec = UJwtDecodeBase64(JwtArr(1) :%len(JwtArr(1)) :*on);
  if (DsDec.Rc < 0);
    Return -1;
  endif;
  Header = DsDec.StringDecodedHex;

  DsDec = UJwtDecodeBase64(JwtArr(2) :%len(JwtArr(2)) :*on);
  if (DsDec.Rc < 0);
    Return -1;
  endif;
  Payload = DsDec.StringDecodedHex;

  DsDec = UJwtDecodeBase64(JwtArr(3) :%len(JwtArr(3)) :*on);
  if (DsDec.Rc < 0);
    Return -1;
  endif;
  Signature = DsDec.StringDecodedHex;
  SignatureLen = %len(%trim(Signature));

  exec sql
    Values (json_value(:Header, '$.alg'  returning varchar(20)))
      into :HashAlg;
  if (SqlState <> '00000');
    return -1;
  endif;

  Idx = %LookUp(HashAlg :DsHash.Arr(*).AlgD);

  DsKey = UJwtGetKey(Header
                    :Payload
                    :DsHash.Arr(Idx).AlgD
                    :*omit
                    :'/home/paolos/jwt_public'
                    :'/home/paolos/jwt_private');

  AlgD0400 = *allx'00';
  AlgD0400.PublicKeyAlgorithm = RSAPUBLICKEYALGORITHM;
  AlgD0400.PKABlockFormat = PKCS1;
  AlgD0400.SigningHashAlgorithm = %Int(DsHash.Arr(Idx).SigningHashAlgorithm);

  KeyD0200 = *allx'00';
  KeyD0200.KeyType      = RSAPUBLICKEYALGORITHM;
  KeyD0200.KeyFormat    = BERSTRING;
  KeyD0200.KeyString    = DsKey.Public;
  KeyD0200.KeyStringLen = DsKey.PublicKeyLength;

  WorkString = JwtArr(1) + '.' +JwtArr(2);

  Qc3VerifySignature(Signature
                    :SignatureLen
                    :WorkString
                    :%len(WorkString)
                    :DATA0100_FMT
                    :AlgD0400
                    :ALGD0400_FMT
                    :KeyD0200
                    :KEYD0200_FMT
                    :ANYCSP
                    :''
                    :ApiError);

  return 0;

End-Proc UJwtVerify;