// Decompiled with JetBrains decompiler
// Type: BNAF.DecryptResponse.RSAPKCS1SHA256SignatureDescription
// Assembly: DecryptResponse, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 03007E77-CB78-4ABE-A8B2-E4A15D152061
// Assembly location: C:\Users\Krishna\OneDrive - NSQUARE XPERTS LLP\Desktop\DecryptResponse.dll

using System;
using System.Security.Cryptography;

namespace BNAF.DecryptResponse
{
  public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
  {
    public RSAPKCS1SHA256SignatureDescription()
    {
      this.KeyAlgorithm = typeof (RSACryptoServiceProvider).FullName;
      this.DigestAlgorithm = typeof (SHA256Managed).FullName;
      this.FormatterAlgorithm = typeof (RSAPKCS1SignatureFormatter).FullName;
      this.DeformatterAlgorithm = typeof (RSAPKCS1SignatureDeformatter).FullName;
    }

    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
      RSAPKCS1SignatureDeformatter deformatter = key != null ? new RSAPKCS1SignatureDeformatter(key) : throw new ArgumentNullException(nameof (key));
      deformatter.SetHashAlgorithm(CryptoConfig.MapNameToOID("SHA256"));
      return (AsymmetricSignatureDeformatter) deformatter;
    }

    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
      RSAPKCS1SignatureFormatter formatter = key != null ? new RSAPKCS1SignatureFormatter(key) : throw new ArgumentNullException(nameof (key));
      formatter.SetHashAlgorithm(CryptoConfig.MapNameToOID("SHA256"));
      return (AsymmetricSignatureFormatter) formatter;
    }
  }
}
