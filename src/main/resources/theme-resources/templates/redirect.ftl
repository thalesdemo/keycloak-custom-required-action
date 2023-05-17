<!DOCTYPE html>
<html>
  <body>
    <#assign path = '/protocol/saml/clients/o365'>
    <#assign redirectUrl = model.url + '/realms/' + model.realm + path>
    <script>
      window.location.href = "${redirectUrl}";
    </script>
  </body>
</html>
