## Jwt parser for Blazor client   
#### blazor.client.jwt
---
#### Note: Currently does not support duplicate claim keys (needs some work).    
All registered and private claims are additionally stored in AppToken.Payload.Claims    

#### Requires nuget packages:
Microsoft.AspNetCore.WebUtilities    
Microsoft.JSInterop.Json    
    


### Example Usage:    
```
JwtTokenParser myTokenParser = new JwtTokenParser();    
AppToken appToken = myTokenParser.ParseToken("yourJwtToken");    
    
Console.WriteLine(appToken.Header.TokenAlgorithm);    
Console.WriteLine(appToken.Payload.TokenExpirationTime.ToString());    
Console.WriteLine(appToken.Payload.GetClaimValueByKey("exp"));
Console.WriteLine(appToken.Payload.ClaimExists("key").ToString());
Console.WriteLine(appToken.GetAsJson());
```

