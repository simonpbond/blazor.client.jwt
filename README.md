# blazor.client.jwt
---
#### Note: Currently does not support duplicate claim keys (needs some work).    
All registered and private claims are additionally stored in AppToken.Payload.Claims    

### Jwt parser for Blazor client    
#### Requires nuget packages:
Microsoft.AspNetCore.WebUtilities    
Utilises: Microsoft.JSInterop.Json    
    


### Usage:    
JwtTokenParser myTokenParser = new JwtTokenParser();    
var appToken = myTokenParser.DeserializeToken("yourJwtToken");    
    
    
Console.WriteLine(appToken.Header.TokenAlgorithm);    
Console.WriteLine(appToken.Payload.TokenExpirationTime.ToString());
Console.WriteLine(appToken.GetClaimValueByKey("exp"));

