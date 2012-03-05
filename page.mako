<div id="verify-form">
%if message:
	<div class="{css_class}">${message}</div>
%endif
<form method="get" accept-charset="UTF-8" action=${action}>
  <input type="text" name="openid_identifier" value=${openid} />
  <input type="submit" value="Verify" /><br />
</form> </div>
