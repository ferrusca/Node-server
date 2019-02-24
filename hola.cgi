#!/usr/bin/python
import cgi, cgitb, os
form = cgi.FieldStorage()
nombre = cgi.escape(form.getvalue('nombre'))
# print "Content-Type: text/html\n"
html = """<html>
<head>
<title>HOLA</title>
</head>
<body style="color:yellow;background-color:blue;margin-top:50px;">
<center>
<h1>Hola %s</h1>
<img
src="https://melbournechapter.net/images/kitten-transparent-white5.png"
width="800px;"/>
</center>
<p style="color:white;">Servidor %s</p>
</body>
</html>
"""
software = os.environ["SERVER_SOFTWARE"]
print html % (nombre, software)