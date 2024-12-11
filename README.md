# Azure-Enum
Enumeración de Azure

Instalar el módulo Microsoft Graph
```powershell
Install-Module Microsoft.Graph
```

Conexión a Microsoft Graph
```powershell
Connect-MgGraph
```

También podemos iniciar sesión usando un token de acceso (obtenido mediante Az, módulo de PowerShell o cualquier otro método)
```powershell
$Token = eyJ0...
Connect-MgGraph –AccessToken ($Token | ConvertTo-SecureString -AsPlainText -Force)
```

Mostrar detalles sobre la sesión activa, como el usuario conectado y la organización en la que se está trabajando.
```powershell
Get-MgContext
```

Obtener información sobre la organización en Microsoft Graph
```powershell
Get-MgOrganization | fl *
```

Listar todos los usuarios
```powershell
Get-MgUser -All
```

Detalle de un usuario específico

```powershell
Get-MgUser -UserId usuario@dominio.com | fl *
```

Búsqueda de usuario que inicien por una letra o *string*
```powershell
Get-MgUser -Filter "startsWith(DisplayName, 'andres')" -ConsistencyLevel eventual
```

Búsqueda de usuarios que contengan la palabra "admin"
```powershell
Get-MgUser -All |?{$_.Displayname -match "admin"}
```

Buscar usuarios en cuyo campo *DisplayName* contenga el valor "admin".
```powershell
Get-MgUser -Search '"DisplayName:admin"' -ConsistencyLevel eventual
```

Búsquea de atributos que contienen la palabra *password*
```powershell
Get-MgUser -All |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ -$($Properties.$_)"}}}
```

Enumerar los usuarios que se sincronizan desde *Om-Premises*
```powershell
Get-MgUser -All | ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

Enumerar los usuarios que solo pertenecen a EntraID
```powershell
Get-MgUser -All | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```

Listar grupos
```powershell
Get-MgGroup -All
```

Detalle de un grupo específico
```powershell
Get-MgGroup -GroupId 000b652e-0aa1-1234-02i2-4412751abb6a
```

Listar los grupos que contengan la palabra 'A'
```powershell
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:A"'
```

Listar los grupos que contengan la palabra 'Admin'
```powershell
Get-MgGroup -ConsistencyLevel eventual -Search '"DisplayName:Admin"'
```

Obtener solo los grupos de Microsoft 365 que tienen membresía dinámica
```powershell
Get-MgGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
```
