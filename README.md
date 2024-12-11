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

Listar los grupos que pertenecen a un usuario
```powershell
Get-MgUserMemberOf -UserId <usuario@correo.com>
```

Listar grupos
```powershell
Get-MgGroup -All
```
Listar los miembros de un grupo
```powershell
Get-MgGroupMember -GroupId <id>
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
Enumerar los grupos que se sincronizan desde *Om-Premises*
```powershell
Get-MgGroup -All| ?{$_.OnPremisesSecurityIdentifier -ne $null}
```

Enumerar los grupos que solo pertenecen a EntraID
```powershell
Get-MgGroup -All | ?{$_.OnPremisesSecurityIdentifier -eq $null}
```
Obtener los grupos y roles, a los cuales pertenece un usuario
```powershell
(Get-MgUserMemberOf -UserId usuario@correo.com).AdditionalProperties
```

## Roles
Listar las plantillas de los roles disponibles
```powershell
Get-MgDirectoryRoleTemplate
```
```powershell
Get-MgDirectoryRoleTemplate | Where-Object {$_.DisplayName -eq "Global Administrator"}
```
Obtener el *RoleId* del rol "*Global Administrator*"
```powershell
$RoleId = (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").Id 
```
Obtener los miembros del rol "*Global Administrator*"
```powershell
(Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId).AdditionalProperties
```

## Dispositivos
Obtener todos los dispositivos registrados
```powershell
Get-MgDevice –All | fl *
```
Obtener los dispositivos dispositivos, exceptuando los obsoletos
```powershell
Get-MgDevice –All | ?{$_.ApproximateLastSignInDateTime -ne $null}
```
Obtener el dueño de los dispositivos registrados
```powershell
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties}
```
```powershell
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredOwner -DeviceId $i).AdditionalProperties.userPrincipalName}
```
Lista de usuarios registrados de todos los dispositivos
```powershell
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties}
```
```powershell
$Ids = (Get-MgDevice –All).Id; foreach($i in $Ids){ (Get-MgDeviceRegisteredUser -DeviceId $i).AdditionalProperties.userPrincipalName}
```
Filtrar solo aquellos dispositivos que son cuentan con las políticas de cumplimiento (aquellos cuyo campo *IsCompliant* es *True*).
```powershell
Get-MgDevice -All| ?{$_.IsCompliant -eq "True"} | fl *
```
Listar los dispositivos que pertencen un usuario.
```powershell
(Get-MgUserOwnedDevice -userId usuario@correo.com).AdditionalProperties
```
Listar los dispositivos registrados por un usuario.
```powershell
(Get-MgUserRegisteredDevice -userId usuario@correo.com).AdditionalProperties
```
## Apps

Obtener todas las aplicaciones
```powershell
Get-MgApplication -All
```
Obtener el detalle de una aplicación
```powershell
Get-MgApplicationByAppId -AppId <AppId> | fl *
```
Detalle de una aplicación, en donde se encuentre la palabra 'app'
```powershell
Get-MgApplication -All | ?{$_.DisplayName -match "app"}
```
 Listar las aplicaciones que tienen configuradas credenciales de tipo contraseña
 ```powershell
 Get-MgApplication -All| ?{$_.PasswordCredentials -ne $null}
```
Obtener el dueño de una aplicación
 ```powershell
(Get-MgApplicationOwner -ApplicationId <Id>).AdditionalProperties.userPrincipalName
 ```
Obtener aplicaciones en las que un usuario tiene un rol (no se muestra el rol exacto)
```powershell
Get-MgUserAppRoleAssignment -UserId usuario@correo.com | fl *
```
Obtener aplicaciones donde un grupo tiene un rol (no se muestra el rol exacto)
```powershell
Get-MgGroupAppRoleAssignment -GroupId <GroupId> | fl *
```
Obtener los *Service Principal*
```powershell
Get-MgServicePrincipal -All
```
Obtener los *Service Principal* por *id*
```powershell
Get-MgServicePrincipal -ServicePrincipalId <Id> | fl *
```
Obtener los *Service Principal* por nombre
```powershell
Get-MgServicePrincipal –All | ?{$_.DisplayName -match "app"}
```
Enumere todos los *Service Principal* con una contraseña de aplicación
```powershell
Get-MgServicePrincipal –All | ?{$_.KeyCredentials -ne $null}
```
Obtener el dueño de un *Service Principal*
```powershell
(Get-MgServicePrincipalOwner -ServicePrincipalId <Id>).AdditionalProperties.userPrincipalName
```
Obtener los objetos (como aplicaciones, grupos, etc.) que están asociados o pertenecen al *Service Principal* especificad
```powershell
Get-MgServicePrincipalOwnedObject -ServicePrincipalId <Id>
```
Obtener objetos creados por un *Service Principal*
```powershell
Get-MgServicePrincipalCreatedObject -ServicePrincipalId <Id>
```
