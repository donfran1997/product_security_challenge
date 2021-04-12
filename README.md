# How to run the app!
1. Navigate to /projects
2. Run run.sh either by sh run.sh
3. Navigate to https://127.0.0.1:5000
4. Create out an account by pressing on the "Register" item in the navbar

Feel free to comment out the pip3 line in run.sh for app runs after that.

Ensure that it is 127.0.0.1 as Google's recaptcha was implemented for that host. 

python3.6 was tested for this project both on Windows 10 WSL and Unbuntu 20.04 so python3-pip is needed.

Tools I used to test my own app burp suit to make sure I can see what is happening in each request and bruteforcing, WireShark to check if SSL/TLS is in placed, sqlmap to test for sql injection, webhooks to see if possible for blind xss or ssrf and manual ssti testing as jinja is being used.
