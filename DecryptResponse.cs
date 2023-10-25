// Decompiled with JetBrains decompiler
// Type: BNAF.DecryptResponse.DecryptResponse
// Assembly: DecryptResponse, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 03007E77-CB78-4ABE-A8B2-E4A15D152061
// Assembly location: C:\Users\Krishna\OneDrive - NSQUARE XPERTS LLP\Desktop\DecryptResponse.dll

using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;

namespace BNAF.DecryptResponse
{
  public class DecryptResponse
  {
    private readonly string DIGEST_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256";
    private readonly string SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    public string ErrorMessage = string.Empty;
    public string hostUrl = string.Empty;

    public string[] Decrypt(string ticket, string clasSessionId, string responseType,    string SignerCertificateSubject)
    {
      string data = HttpUtility.UrlDecode(this.Post2Server(this.hostUrl + "/bnaf/reqStatus.do;jsessionid=" + clasSessionId, "ticket=" + ticket));
      if (responseType == "KV")
      {
        string xml = this.base64Decode(data);
        XmlDocument doc = new XmlDocument();
        doc.PreserveWhitespace = false;
        doc.LoadXml(xml);
        return this.Decrypt(doc, SignerCertificateSubject);
      }
      StreamReader streamReader = new StreamReader(AppDomain.CurrentDomain.BaseDirectory + "Certificates\\SAMLResponseHTML.htm");
      string end = streamReader.ReadToEnd();
      string[] strArray;
      try
      {
        strArray = data.Split('&');
        this.base64Decode(strArray[0]);
        if (strArray != null && strArray.Length > 1)
        {
          string str1 = end.Replace("status", strArray[1].Split('=')[1]).Replace("userid", strArray[2].Split('=')[1]).Replace("llogin", strArray[3].Split('=')[1]).Replace("lfailed", strArray[4].Split('=')[1]).Replace("addresreplace", strArray[5].Split('=')[1]).Replace("scard", strArray[6].Split('=')[1]).Replace("expirycard", strArray[7].Split('=')[1]).Replace("samltoken", strArray[0]).Replace("registrationType", strArray[8].Split('=')[1]).Replace("authid", strArray[9].Split('=')[1]).Replace("authIdTimestamp", strArray[10].Split('=')[1]).Replace("dob", strArray[11].Split('=')[1]);
          string newValue = string.Empty;
          string str2;
          if (strArray.Length > 12)
          {
            string str3 = strArray[12].Split('=')[1];
            char[] chArray = new char[1]{ '#' };
            foreach (string str4 in str3.Split(chArray))
              newValue = newValue + str4 + "<br />";
            str2 = str1.Replace("corppassdetails", newValue);
          }
          else
            str2 = str1.Replace("Corp Pass Details&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; :", "").Replace("corppassdetails", "");
          str2.Replace("englishName", strArray[13].Split('=')[1]).Replace("arabicName", strArray[14].Split('=')[1]).Replace("eServiceID", strArray[15].Split('=')[1]).Replace("nationality", strArray[16].Split('=')[1]).Replace("youloggedinas", strArray[1].Split('=')[1]);
        }
      }
      catch (Exception ex)
      {
        throw ex;
      }
      finally
      {
        streamReader.Close();
      }
      return strArray;
    }

    public X509Certificate2 GetCertificateBySubject(string CertificateSubject)
    {

      if (CertificateSubject == null)
        throw new ArgumentNullException(nameof (CertificateSubject));
      X509Certificate2 certificateBySubject = (X509Certificate2) null;
      X509Store x509Store = new X509Store(StoreLocation.LocalMachine) ?? new X509Store(StoreLocation.CurrentUser);
      try
      {
        x509Store.Open(OpenFlags.OpenExistingOnly);
        X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
        while (enumerator.MoveNext())
        {
          X509Certificate2 current = enumerator.Current;
          if (current.Subject == CertificateSubject)
          {
            certificateBySubject = current;
            break;
          }
        }
        if (certificateBySubject == null)
          throw new CryptographicException("The certificate could not be found.");
      }
      finally
      {
        x509Store.Close();
      }
      return certificateBySubject;
    }

    public string base64Decode(string data)
    {
      try
      {
        Decoder decoder = new UTF8Encoding().GetDecoder();
        byte[] bytes = Convert.FromBase64String(data);
        char[] chars = new char[decoder.GetCharCount(bytes, 0, bytes.Length)];
        decoder.GetChars(bytes, 0, bytes.Length, chars, 0);
        return new string(chars);
      }
      catch (Exception ex)
      {
        throw new Exception("Error in base64Decode" + ex.Message);
      }
    }

    public string base64Encode1(string data)
    {
      try
      {
        byte[] numArray = new byte[data.Length];
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
      }
      catch (Exception ex)
      {
        throw new Exception("Error in base64Encode" + ex.Message);
      }
    }

    private string[] Decrypt(XmlDocument doc, string SignerCertificateSubject)
    {
      StreamReader streamReader = new StreamReader(AppDomain.CurrentDomain.BaseDirectory + "Certificates\\ResponseHTML.htm");
      streamReader.ReadToEnd();
      string[] strArray;
      try
      {
        XmlElement element = BNAF.DecryptResponse.DecryptResponse.GetElement("EncryptedData", "http://www.w3.org/2001/04/xmlenc#", doc);
        EncryptedData encryptedData = new EncryptedData();
        encryptedData.LoadXml(element);
        XmlNodeList elementsByTagName = doc.GetElementsByTagName("KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.LoadXml((XmlElement) elementsByTagName[0]);
        X509Certificate2 certificateBySubject = this.GetCertificateBySubject(SignerCertificateSubject);
        SymmetricAlgorithm symmetricAlgorithm = (SymmetricAlgorithm) null;
        foreach (KeyInfoClause keyInfoClause in keyInfo)
        {
          if (keyInfoClause is KeyInfoEncryptedKey)
          {
            EncryptedKey encryptedKey = ((KeyInfoEncryptedKey) keyInfoClause).EncryptedKey;
            symmetricAlgorithm = (SymmetricAlgorithm) new RijndaelManaged();
            symmetricAlgorithm.Key = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (RSA) certificateBySubject.PrivateKey, false);
          }
        }
        byte[] bytes = new EncryptedXml().DecryptData(encryptedData, symmetricAlgorithm);
        XmlDocument doc1 = new XmlDocument();
        doc1.Load((TextReader) new StringReader(Encoding.UTF8.GetString(bytes)));
        strArray = BNAF.DecryptResponse.DecryptResponse.GetElement("BNAFAuthStatus", "", doc1).InnerText.Split('&');
      }
      catch (Exception ex)
      {
        throw ex;
      }
      finally
      {
        streamReader.Close();
      }
      return strArray;
    }

    private static XmlElement GetElement(string element, string ns, XmlDocument doc) => (XmlElement) doc.GetElementsByTagName(element, ns)[0];

    public string EncryptAndSignDoc(
      string agencyID,
      string returnUrl,
      string authnLevel,
      string locale,
      string respType,
      string SignerCertificateSubject,
      string EncryptionCertificateSubject,
      string isCorppassResponse)
    {
      try
      {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BNAF><BNAFAuthRequest>eserviceId=" + agencyID + "&amp;returnUrl=" + returnUrl + "&amp;authnLevel=" + authnLevel + "&amp;locale=" + locale + "&amp;respType=" + respType + "&amp;isCorpPassResponse=" + isCorppassResponse + "</BNAFAuthRequest></BNAF>";
        X509Certificate2 certificateBySubject1 = this.GetCertificateBySubject(EncryptionCertificateSubject);
        X509Certificate2 certificateBySubject2 = this.GetCertificateBySubject(SignerCertificateSubject);
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        XmlDocument doc = this.Encrypt(xml, "BNAF", certificateBySubject1);
        RSACryptoServiceProvider privateKey = this.ConstructRSAPrivateKey(certificateBySubject2);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(this.Sign(doc, certificateBySubject2, privateKey).InnerXml));
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public string EncryptAndSignDoc(
      string agencyID,
      string returnUrl,
      string authnLevel,
      string locale,
      string respType,
      string SignerCertificateSubject,
      string EncryptionCertificateSubject,
      string isCorppassResponse,
      bool isAllowGCCUserLogin)
    {
      try
      {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BNAF><BNAFAuthRequest>eserviceId=" + agencyID + "&amp;returnUrl=" + returnUrl + "&amp;authnLevel=" + authnLevel + "&amp;locale=" + locale + "&amp;respType=" + respType + "&amp;isCorpPassResponse=" + isCorppassResponse + "&amp;isAllowGCCUserLogin=" + isAllowGCCUserLogin.ToString() + "</BNAFAuthRequest></BNAF>";
        X509Certificate2 certificateBySubject1 = this.GetCertificateBySubject(EncryptionCertificateSubject);
        X509Certificate2 certificateBySubject2 = this.GetCertificateBySubject(SignerCertificateSubject);
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        XmlDocument doc = this.Encrypt(xml, "BNAF", certificateBySubject1);
        RSACryptoServiceProvider privateKey = this.ConstructRSAPrivateKey(certificateBySubject2);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(this.Sign(doc, certificateBySubject2, privateKey).InnerXml));
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public string EncryptAndSignDoc(
      string agencyID,
      string returnUrl,
      string authnLevel,
      string locale,
      string respType,
      string SignerCertificateSubject,
      string EncryptionCertificateSubject,
      bool isAllowGCCUserLogin)
    {
      try
      {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BNAF><BNAFAuthRequest>eserviceId=" + agencyID + "&amp;returnUrl=" + returnUrl + "&amp;authnLevel=" + authnLevel + "&amp;locale=" + locale + "&amp;respType=" + respType + "&amp;isAllowGCCUserLogin=" + isAllowGCCUserLogin.ToString() + "</BNAFAuthRequest></BNAF>";
        X509Certificate2 certificateBySubject1 = this.GetCertificateBySubject(EncryptionCertificateSubject);
        X509Certificate2 certificateBySubject2 = this.GetCertificateBySubject(SignerCertificateSubject);
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        XmlDocument doc = this.Encrypt(xml, "BNAF", certificateBySubject1);
        RSACryptoServiceProvider privateKey = this.ConstructRSAPrivateKey(certificateBySubject2);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(this.Sign(doc, certificateBySubject2, privateKey).InnerXml));
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public string EncryptAndSignDoc(
      string agencyID,
      string returnUrl,
      string authnLevel,
      string locale,
      string respType,
      string SignerCertificateSubject,
      string EncryptionCertificateSubject)
    {
      try
      {
        string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BNAF><BNAFAuthRequest>eserviceId=" + agencyID + "&amp;returnUrl=" + returnUrl + "&amp;authnLevel=" + authnLevel + "&amp;locale=" + locale + "&amp;respType=" + respType + "</BNAFAuthRequest></BNAF>";
        X509Certificate2 certificateBySubject1 = this.GetCertificateBySubject(EncryptionCertificateSubject);
        X509Certificate2 certificateBySubject2 = this.GetCertificateBySubject(SignerCertificateSubject);
        ASCIIEncoding asciiEncoding = new ASCIIEncoding();
        XmlDocument doc = this.Encrypt(xml, "BNAF", certificateBySubject1);
        RSACryptoServiceProvider privateKey = this.ConstructRSAPrivateKey(certificateBySubject2);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(this.Sign(doc, certificateBySubject2, privateKey).InnerXml));
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public XmlDocument Encrypt(string xml, string xmlNodeToEncrypt, X509Certificate2 certificate)
    {
      if (string.IsNullOrEmpty(xml))
        throw new ArgumentNullException(nameof (xml));
      if (string.IsNullOrEmpty(xmlNodeToEncrypt))
        throw new ArgumentNullException("xmlElementToEncrypt");
      if (certificate == null)
        throw new ArgumentNullException(nameof (certificate));
      XmlDocument xmlDocument = new XmlDocument();
      xmlDocument.PreserveWhitespace = false;
      xmlDocument.LoadXml(xml);
      if (!(xmlDocument.GetElementsByTagName(xmlNodeToEncrypt)[0] is XmlElement inputElement))
        throw new ArgumentException("The specified element was not found in XML string", "xmlElementToEncrypt");
      Rijndael rijndael = (Rijndael) null;
      try
      {
        rijndael = (Rijndael) new RijndaelManaged();
        rijndael.KeySize = 256;
        byte[] numArray = new EncryptedXml().EncryptData(inputElement, (SymmetricAlgorithm) rijndael, false);
        EncryptedData encryptedData = new EncryptedData();
        encryptedData.Type = "http://www.w3.org/2001/04/xmlenc#Element";
        encryptedData.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        EncryptedKey encryptedKey = new EncryptedKey();
        byte[] cipherValue = EncryptedXml.EncryptKey(rijndael.Key, (RSA) certificate.PublicKey.Key, false);
        encryptedKey.CipherData = new CipherData(cipherValue);
        encryptedKey.EncryptionMethod = new EncryptionMethod("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        KeyInfoX509Data clause = new KeyInfoX509Data();
        string issuerName = certificate.Issuer.Replace("S=", "ST=");
        clause.AddIssuerSerial(issuerName, certificate.GetSerialNumberString());
        encryptedKey.KeyInfo.AddClause((KeyInfoClause) clause);
        encryptedData.KeyInfo.AddClause((KeyInfoClause) new KeyInfoEncryptedKey(encryptedKey));
        encryptedData.CipherData.CipherValue = numArray;
        EncryptedXml.ReplaceElement(inputElement, encryptedData, false);
      }
      catch (Exception ex)
      {
        throw ex;
      }
      finally
      {
        rijndael?.Clear();
      }
      return xmlDocument;
    }

    public XmlDocument Sign(
      XmlDocument doc,
      X509Certificate2 agencyCertificate,
      RSACryptoServiceProvider privateKey)
    {
      try
      {
        CryptoConfig.AddAlgorithm(typeof (RSAPKCS1SHA256SignatureDescription), this.SIGNATURE_METHOD);
        if (doc == null)
          throw new ArgumentNullException(nameof (doc));
        if (agencyCertificate == null)
          throw new ArgumentNullException(nameof (agencyCertificate));
        if (privateKey == null)
          throw new ArgumentNullException(nameof (privateKey));
        doc.PreserveWhitespace = false;
        SignedXml signedXml = new SignedXml(doc);
        Reference reference = new Reference("");
        XmlDsigEnvelopedSignatureTransform signatureTransform = new XmlDsigEnvelopedSignatureTransform();
        reference.AddTransform((Transform) signatureTransform);
        reference.DigestMethod = this.DIGEST_METHOD;
        KeyInfo keyInfo = new KeyInfo();
        KeyInfoX509Data clause = new KeyInfoX509Data();
        string issuerName = agencyCertificate.Issuer.Replace("S=", "ST=");
        clause.AddIssuerSerial(issuerName, agencyCertificate.GetSerialNumberString());
        keyInfo.AddClause((KeyInfoClause) clause);
        signedXml.SigningKey = (AsymmetricAlgorithm) privateKey;
        System.Security.Cryptography.Xml.Signature signature = signedXml.Signature;
        signature.SignedInfo.AddReference(reference);
        signature.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        signature.SignedInfo.SignatureMethod = this.SIGNATURE_METHOD;
        signature.KeyInfo = keyInfo;
        signedXml.ComputeSignature();
        XmlElement xml = signedXml.GetXml();
        doc.DocumentElement.AppendChild(doc.ImportNode((XmlNode) xml, true));
        return doc;
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public string Post2Server(string url, string value)
    {
      HttpWebRequest httpWebRequest = WebRequest.Create(url) as HttpWebRequest;
      httpWebRequest.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
      httpWebRequest.Headers.Add("Pragma: no-cache");
      httpWebRequest.Method = "POST";
      httpWebRequest.AllowAutoRedirect = false;
      try
      {
        using (Stream requestStream = httpWebRequest.GetRequestStream())
        {
          string str = value + "=" + HttpUtility.UrlEncode(value);
          requestStream.Write(Encoding.UTF8.GetBytes(value), 0, value.Length);
        }
      }
      catch (WebException ex)
      {
        throw ex;
      }
      try
      {
        using (HttpWebResponse response = (HttpWebResponse) httpWebRequest.GetResponse())
        {
          using (Stream responseStream = response.GetResponseStream())
          {
            using (StreamReader streamReader = new StreamReader(responseStream, Encoding.UTF8))
              return streamReader.ReadToEnd();
          }
        }
      }
      catch (WebException ex)
      {
        if (ex.Response != null)
        {
          using (Stream responseStream = ex.Response.GetResponseStream())
          {
            using (StreamReader streamReader = new StreamReader(responseStream))
              this.ErrorMessage = streamReader.ReadToEnd();
          }
        }
      }
      return (string) null;
    }

    public RSACryptoServiceProvider ConstructRSAPrivateKey(X509Certificate2 keyPair)
    {
      try
      {
        RSACryptoServiceProvider privateKey = keyPair.PrivateKey as RSACryptoServiceProvider;
        RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
        if (Environment.Version.Major >= 4)
        {
          byte[] keyBlob = privateKey.ExportCspBlob(true);
          cryptoServiceProvider.ImportCspBlob(keyBlob);
        }
        else
        {
          RSAParameters parameters = privateKey.ExportParameters(true);
          cryptoServiceProvider.ImportParameters(parameters);
        }
        return cryptoServiceProvider;
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

    public X509Certificate2 GetCertBySubject(string fileName)
    {
      X509Certificate2 x509Certificate2 = new X509Certificate2();
      X509Certificate2 certBySubject;
      try
      {
        string fileName1 = AppDomain.CurrentDomain.BaseDirectory + "Certificates\\" + fileName;
        string password = "password";
        X509Certificate2Collection certificate2Collection = new X509Certificate2Collection();
        certificate2Collection.Import(fileName1, password, X509KeyStorageFlags.Exportable);
        certBySubject = certificate2Collection[0];
      }
      catch (Exception ex)
      {
        throw ex;
      }
      return certBySubject;
    }
  }
}
