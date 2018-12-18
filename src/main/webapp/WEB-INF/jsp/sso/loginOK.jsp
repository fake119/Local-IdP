<!DOCTYPE html>
<html>
<head>
	<title>SAML Generator</title>
	<link rel='stylesheet' href='/stylesheets/style.css' />
</head>
<body style="display:block;">
<h4>SAML Generate Form</h4>
<form method="post" action="" onsubmit="return false;">
	<br>Plain SAML XML<br>
	<textarea name="rawSAMLResponse" id="rawSAMLResponse" rows="30" cols="100">${signedSAML}</textarea>
</form>
<hr><br>
<h4>Login Form</h4>
<form id="frmSAML" method="post" action="${recipientURL}">
	<br>recipient<br>
	<input type="text" name="recipientURL" size="100" value="${recipientURL}" readonly="readonly">
	<br>Base64<br>
	<input type="text" name="SAMLResponse" size="100" value="${samlResponse}">
	<br>RelayState<br>
	<input type="text" name="RelayState" size="100" value="${relayState}">
	<br>
	<input type="submit" id="samlPoster_0" value="Login">
</form>
</body>
<script type="text/javascript">
//document.getElementById("frmSAML").submit();
</script>
</html>