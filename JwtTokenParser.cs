using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.JSInterop;

namespace Blazor.Client.Jwt
{
    public class JwtTokenParser
    {

        public AppToken ParseToken(string encodedToken)
        {
            AppToken appToken = new AppToken();
            try
            {
                string[] tokenSections = encodedToken.Split('.');

                byte[] decodedHeaderBytes = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(tokenSections[0]);
                var decodedHeaderJson = System.Text.Encoding.UTF8.GetString(decodedHeaderBytes);
                var headerDictionary = new Dictionary<string, object>();
                headerDictionary = Microsoft.JSInterop.Json.Deserialize<Dictionary<string, object>>(decodedHeaderJson);

                byte[] decodedPayloadBytes = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(tokenSections[1]);
                var decodedPayloadJson = System.Text.Encoding.UTF8.GetString(decodedPayloadBytes);
                var payloadDictionary = new Dictionary<string, object>();
                payloadDictionary = Microsoft.JSInterop.Json.Deserialize<Dictionary<string, object>>(decodedPayloadJson);


                appToken.Header = new AppToken.AppTokenHeader()
                {
                    TokenAlgorithm = headerDictionary.ContainsKey("alg") ? headerDictionary.Where(claim => claim.Key == "alg").SingleOrDefault().Value.ToString() : string.Empty,
                    TokenType = headerDictionary.ContainsKey("typ") ? headerDictionary.Where(claim => claim.Key == "typ").SingleOrDefault().Value.ToString() : string.Empty
                };

                var dateTimeEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

                appToken.Payload = new AppToken.AppTokenPayload()
                {
                    Claims = payloadDictionary.ToDictionary(claims => claims.Key, claims => claims.Value.ToString()),

                    TokenJwtIdentifier = payloadDictionary.ContainsKey("jti") ? payloadDictionary.Where(claim => claim.Key == "jti").SingleOrDefault().Value.ToString() : string.Empty,
                    TokenUniqueName = payloadDictionary.ContainsKey("unique_name") ? payloadDictionary.Where(claim => claim.Key == "unique_name").SingleOrDefault().Value.ToString() : string.Empty,
                    TokenSubject = payloadDictionary.ContainsKey("sub") ? payloadDictionary.Where(claim => claim.Key == "sub").SingleOrDefault().Value.ToString() : string.Empty,
                    TokenAudience = payloadDictionary.ContainsKey("aud") ? payloadDictionary.Where(claim => claim.Key == "aud").SingleOrDefault().Value.ToString() : string.Empty,
                    TokenExpirationTime = dateTimeEpoch.AddSeconds(int.Parse(payloadDictionary.ContainsKey("exp") ? payloadDictionary.Where(claim => claim.Key == "exp").SingleOrDefault().Value.ToString() : "0")),
                    TokenNotBeforeTime = dateTimeEpoch.AddSeconds(int.Parse(payloadDictionary.ContainsKey("nbf") ? payloadDictionary.Where(claim => claim.Key == "nbf").SingleOrDefault().Value.ToString() : "0")),
                    TokenIssuedAt = dateTimeEpoch.AddSeconds(int.Parse(payloadDictionary.ContainsKey("iat") ? payloadDictionary.Where(claim => claim.Key == "iat").SingleOrDefault().Value.ToString() : "0")),
                    TokenIssuer = payloadDictionary.ContainsKey("iss") ? payloadDictionary.Where(claim => claim.Key == "iss").SingleOrDefault().Value.ToString() : string.Empty
                };

            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: Could not parse token: " + ex.Message + "\n" + ex.StackTrace);
            }

            return appToken;
        }

        public class AppToken
        {
            public AppTokenHeader Header { get; set; }
            public AppTokenPayload Payload { get; set; }

            public string GetAsJson()
            {
                var json = Microsoft.JSInterop.Json.Serialize(this);
                return json;
            }

            public class AppTokenHeader
            {
                public string TokenAlgorithm { get; set; }
                public string TokenType { get; set; }
            }

            public class AppTokenPayload
            {
                public string TokenIssuer { get; set; }
                public string TokenSubject { get; set; }
                public string TokenUniqueName { get; set; }
                public string TokenAudience { get; set; }
                public DateTime TokenExpirationTime { get; set; }
                public DateTime TokenNotBeforeTime { get; set; }
                public DateTime TokenIssuedAt { get; set; }
                public string TokenJwtIdentifier { get; set; }
                public Dictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();

                public string GetClaimValueByKey(string key)
                {
                    string value = string.Empty;
                    Claims.TryGetValue(key, out value);
                    return value;

                }

                public bool ClaimExists(string key)
                {
                    if (Claims.ContainsKey(key)) { return true; } else { return false; }
                }
            }
        }
    }
}
