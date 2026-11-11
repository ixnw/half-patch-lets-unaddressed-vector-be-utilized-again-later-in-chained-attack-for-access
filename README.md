# Initial vector discovery and use-case (CWE-200, CWE-346)
Password reset link poisoning via attacker controlled baseUrl leads to reset token exposure and possible account takeover:

https://github.com/user-attachments/assets/39110aa1-3b91-4ca0-865c-9f1271cc635f

The forgot-password endpoint trusts a user supplied baseUrl when generating reset links. This allows an attacker to trigger a legitimate password reset email to a victim that contains an attacker controlled link. When clicked, the victim’s browser sends the victim’s email and reset token to the attacker’s domain: 
**https://[attacker controled domain]/?email=[victim email]&token=[victim token]** 
thus allowing the attacker to reuse the token on the legitimate reset-password page: 
**https://app.candid.org/reset-password?email=[victim email]&token=[victim token]**
Allowing flawless account takeover.

# How this vulnerability was initially resolved and why the resolution was only a temporary work around



# The result of this work around was...
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

# Written PoC of full attack chain, start to finish, vector \#1 to session hijack 
[Overview.pdf-shop.candid.org Password Reset Poisoning to Session Hijacking via Open Redirect and XSS.pdf-2.pdf](https://github.com/user-attachments/files/34662269/Overview.pdf-shop.candid.org.Password.Reset.Poisoning.to.Session.Hijacking.via.Open.Redirect.and.XSS.pdf-2.pdf)
