# Azure-Enum

- [MicrosoftGraph](#Microsoft-Graph)
- [AzPowerShell](#Az-PowerShell)

### Microsoft Graph
Instalar el módulo Microsoft Graph
```powershell****
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
### Usuarios
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
### Grupos
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
### Roles
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
### Dispositivos
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
### Apps

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
Obtener los grupos o roles de EntraId de los que es miembro un S*Service Principal* específico.
```powershell
Get-MgServicePrincipalMemberOf -ServicePrincipalId <Id> | fl *
```

### Az PowerShell
Para conectarse
```powershell
Connect-AzAccount
```
Imprimir datos del contexto actual
```powershell
Get-AzContext
```
Listar todos los contextos disponibles
```powershell
Get-AzContext -ListAvailable
```
Enumerar las suscripciones a las cuales el usuario actual puede acceder
```powershell
Get-AzSubscription
```
Enumerar los recursos visbles para el usuario actual
```powershell
Get-AzResource
```
Enumerar todas las asignaciones de roles de Azure RBAC
```powershell
Get-AzRoleAssignment
```
### Usuarios
Enumerar todos los usuarios
```powershell
Get-AzADUser
```
Detalles de un usuario específico
```powershell
Get-AzADUser -UserPrincipalName usuario@correo.com
```
Búsqueda de usuarios que contengan la palabra "admin"
```powershell
Get-AzADUser -SearchString "admin"
```
Buscar usuarios que contengan la palabra "admin" en su nombre:
Get-AzADUser |?{$_.Displayname -match "admin"}
### Grupos
Listar los grupos
```powershell
Get-AzADGroup
```
Enumerar un grupo específico
```powershell
Get-AzADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e
```
Listar los grupos que contengan la palabra 'admin'
```powershell
Get-AzADGroup -SearchString "admin" | fl *
```
Listar los grupos que contengan la palabra 'admin'
```powershell
Get-AzADGroup |?{$_.Displayname -match "admin"}
```
Listar los miembros de un grupo
```powershell
Get-AzADGroupMember -ObjectId <Id>
```
### Apps

Obtener las aplicaciones registradas en el *Tenant* actual
```powershell
Get-AzADApplication
```
Obtener detalles de una aplicación específica
```powershell
Get-AzADApplication -ObjectId <Id>
```
Obtener detalle de una aplicación que conincide con una palabra
```powershell
Get-AzADApplication | ?{$_.DisplayName -match "app"}
```
Obtiener todas las aplicaciones y filtra aquellas que tienen credenciales asociadas.
```powershell
Get-AzADApplication | %{if(Get-AzADAppCredential -ObjectID $_.ID){$_}}
```
### *Service Principals*
Obtener los *Service Principal*
```powershell
Get-AzADServicePrincipal
```
Obtener los *Service Principal* por *id*
```powershell
Get-AzADServicePrincipal -ObjectId <Id>
```
Obtener los *Service Principal* por nombre
```powershell
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"}
```
### Azure CLI
Ingreso
```powershell
az login
```
```powershell
az login -u usuario@correo.com -p Password1
```
Si el usuario NO tiene permisos en la suscripción
```powershell
az login -u usuario@correo.com -p Password1 --allow-no-subscriptions
```

Detalle del usuario actual
```powershell
az account tenant list
```
Detalle de la suscripción actual
```powershell
az account subscription list
```
Listar detalles del usuario que realizó el ingreso
```powershell
az ad signed-in-user show
```

### Usuarios
Listar los usuarios de EntraID
```powershell
az ad user list --output table
```
```powershell
az ad user list
```
```powershell
az ad user list --query "[].[displayName]" -o table
```
```powershell
az ad user list --query "[].[userPrincipalName,displayName]" --output table
```
```powershell
az ad user list --query "[].{UPN:userPrincipalName, Name:displayName}" --output table
```
Enumerar detalles de un usuario particular
```powershell
az ad user show --id usuario@correo.com
```
Búsqueda de usuarios que contengan la palabra "admin" (*Case-sensitive*)
```powershell
az ad user list --query "[?contains(displayName,'admin')].displayName"
```
Búsqueda de usuarios que contengan la palabra "admin" (*Not case-sensitive*)
```powershell
az ad user list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```
Usuarios sincronizados con *Om-Premises*
```powershell
az ad user list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```
Usuarios que son de EntraID
```powershell
az ad user list --query "[?onPremisesSecurityIdentifier==null].displayName"
```
### Grupos
Listar grupos
```powershell
az ad group list
az ad group list --query "[].[displayName]" -o table
```
Enumerar un grupo por nombre o por id
```powershell
az ad group show -g "VM Admins"
```
```powershell
az ad group show -g 783a312d-0de2-4490-92e4-539b0e4ee03e
```
Buscar grupos que contienen la palabra "admin" en *Display name* (*case-sensitive*)
```powershell
az ad group list --query "[?contains(displayName,'admin')].displayName"
```
Búsqueda de usuarios que contengan la palabra "admin" (*Not case-sensitive*)
```powershell
az ad group list | ConvertFrom-Json | %{$_.displayName -match "admin"}
```
Enumerar los grupos que se sincronizan desde *Om-Premises*
```powershell
az ad group list --query "[?onPremisesSecurityIdentifier!=null].displayName"
```
Enumerar los grupos que solo pertenecen a EntraID
```powershell
az ad group list --query "[?onPremisesSecurityIdentifier==null].displayName"
```
Obtener miembros de un grupo
```powershell
az ad group member list -g "<GRUPO>" --query "[].[displayName]" -o table
```
Buscar si un usuario es miembro de un grupo
```powershell
az ad group member check --group "<GRUPO>" --member-id <Id>
```
### Apps
Obtener todos los objetos de aplicación registrados en el *tenant*
```powershell
az ad app list
az ad app list --query "[].{AppName: displayName, AppId: appId}" -o table
```
Obtener el detalle de una aplicación
```powershell
az ad app show --id
```
Obtener detalle de una aplicación que conincide con una palabra 'app'
```powershell
az ad app list --query "[?contains(displayName,'app')].displayName"
```
Búsqueda de usuarios que contengan la palabra "admin" (*not case-sensitive*)
```powershell
az ad app list | ConvertFrom-Json | %{$_.displayName -match "app"}
```
Buscar quién es el dueño de una aplicación
```powershell
az ad app owner list --id <Id>
```
Enumere todos los *Service Principal* con una contraseña de aplicación
```powershell
az ad app list --query "[?passwordCredentials !=null].displayName"
```
Listar las aplicaciones que tienen algún tipo de clave o certificado configurado para su autenticación
```powershell
az ad app list --query "[?keyCredentials !=null].displayName"
```
### AAD Service Principals

Obtener los *Service Principals*
```powershell
az ad sp list --all --query "[].{Name: displayName, SPId: appId}" -o table
```
Obtener el detalle de un *Service Principals*
```powershell
az ad sp show --id <Id>
```
Obtener el *Service Principals* a través del nombre
```powershell
az ad sp list --all --query "[?contains(displayName,'app')].displayName"
```
Búsqueda de usuarios que contengan la palabra "app" (*not case-sensitive*)
```powershell
az ad sp list --all | ConvertFrom-Json | %{$_.displayName -match "app"}
```
Obtener el dueño de un *Service Principals*
```powershell
az ad sp owner list --id <Id> --query "[].[displayName]" -o table
```
Obtenber los *Service Principals* que pertenecen al usuario actual
```powershell
az ad sp list --show-mine
```
Enumere todos las aplicaciones con una contraseña de aplicación
```powershell
az ad sp list --all --query "[?passwordCredentials != null].displayName"
```
Obtener los nombres de las aplicaciones que tienen configuradas claves o certificados.
```powershell
az ad app list --query "[?keyCredentials != null].displayName" -o table

```
