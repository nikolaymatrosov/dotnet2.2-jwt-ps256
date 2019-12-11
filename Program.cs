using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using Jose;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace jose_jwt_test
{
    class Program
    {
        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.D = privKey.Exponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.DP = privKey.DP.ToByteArrayUnsigned();
            rp.DQ = privKey.DQ.ToByteArrayUnsigned();
            rp.InverseQ = privKey.QInv.ToByteArrayUnsigned();
            return rp;
        }
        static void Main(string[] args)
        {
            var serviceAccountId = "%serviceAccountId%";
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            JwtPayload payload = new JwtPayload();
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
            payload.Add("aud", "https://iam.api.cloud.yandex.net/iam/v1/tokens");
            payload.Add("iss", serviceAccountId);
            payload.Add("iat", now);
            payload.Add("exp", now + 3600);

            var reader = File.OpenText("./private.key");
            PemReader pRd = new PemReader(reader);
            RsaPrivateCrtKeyParameters pKey = (RsaPrivateCrtKeyParameters)pRd.ReadObject();
            pRd.Reader.Close();

            var RSAOpenSsl = new RSAOpenSsl(ToRSAParameters(pKey));

            IDictionary<string, object> dict = new Dictionary<string, object>();
            dict.Add("kid", "ajerfj2gvc0rf20si9ot");
            dict.Add("typ", "JWT");

            string token = Jose.JWT.Encode(payload.SerializeToJson(), RSAOpenSsl, JwsAlgorithm.PS256, dict);
            Console.WriteLine(token);
        }
    }
}
