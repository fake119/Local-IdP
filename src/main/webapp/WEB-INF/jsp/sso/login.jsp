<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Login</title>
<script type="text/javascript" src="/js/lib/jquery-1.11.0.min.js"></script>
</head>
<body>
<h4>IDP LOGIN(SSO LOGIN)</h4>
<form method="post" name="frmLogin" id="frmLogin" action="loginOK">
	<input type="text" name="relayState" value="${relayState}">
	<input type="text" name="email" placeholder="email" id="email" value=""></input>
	<input type="password" name="password" placeholder="password" id="password"></input>
	<input type="submit" value="Login" name="btnLogin" id="btnLogin"></input>
</form>
</body>
</html>
