# NetGuardian

Herramienta de administracion de red local para Windows (estilo NetCut).
Escrita en C# / .NET 8 con Windows Forms, SharpPcap y PacketDotNet.
Tema oscuro negro/azul.

## AVISO LEGAL Y ETICO

Esta aplicacion usa ARP spoofing para interceptar y bloquear trafico de
dispositivos de la red. Usarla en una red que no sea de tu propiedad o sin
autorizacion expresa de su propietario es ILEGAL en la mayoria de paises
(configura delitos de acceso o alteracion de sistemas). El proyecto se
publica solo con fines educativos y de administracion de redes propias.

## Captura de funcionalidades

| Funcion | Descripcion |
|---|---|
| Escaneo de red | Ping sweep /24 + tabla ARP: IP, MAC, fabricante, nombre, SO |
| Fabricante (OUI) | Base embebida de ~200 fabricantes (+ deteccion de MAC privada/aleatoria) |
| Nombre real | Zeroconf/DNS-SD (nuget: Zeroconf, `BrowseDomainsAsync` + `ResolveAsync`), NetBIOS (UDP 137) para Windows, mDNS propio como respaldo, DNS inverso como ultima reserva |
| SO estimado | Huella TTL refinada con fabricante y NetBIOS |
| Vigilancia (MITM) | Enruta el trafico de la victima por esta maquina (con reenvio) para medir bajada y subida reales |
| Bloqueo | ARP spoofing: el trafico de la victima se redirige aqui y se descarta |
| Limite de velocidad | Veneno ARP ciclico (aproximado, en KB/s) |
| Monitor en tiempo real | KB/s por dispositivo refrescados cada segundo |
| Registro | Log en pantalla y archivo `netguardian.log` junto al .exe |

## Requisitos

- Windows 10/11 x64
- Npcap instalado: https://npcap.com (marca la opcion
  "WinPcap API-compatible mode" al instalar)
- Privilegios de administrador (el .exe los pide por UAC automaticamente)

## Uso rapido

1. Instala Npcap.
2. Ejecuta `NetGuardian.exe` como administrador.
3. Pulsa **Escanear red** y espera ~10 segundos.
4. Selecciona un dispositivo en la tabla:
   - **Vigilar trafico**: mide su consumo real de subida y bajada.
   - **Bloquear** / **Desbloquear**: corta o restaura su internet.
   - **Limitar velocidad**: aplica un limite aproximado en KB/s.

Al salir, la aplicacion restaura automaticamente las tablas ARP de todos
los dispositivos afectados.

## Estructura del proyecto

```
NetGuardian/
  NetGuardian.csproj          Proyecto (single-file, self-contained, UAC)
  app.manifest                requireAdministrator
  Program.cs                  Punto de entrada
  Models/
    NetworkDevice.cs          Modelo de dispositivo (IP, MAC, vendor, SO...)
  Modules/
    NetworkScanner.cs         Escaneo: ping + ARP + NetBIOS + mDNS + DNS
    ArpSpoofer.cs             ARP spoofing (bloqueo y vigilancia MITM)
    TrafficMonitor.cs         Captura, conteo de trafico y reenvio
    BandwidthLimiter.cs       Limitacion de velocidad aproximada
  Utils/
    Logger.cs                 Registro de actividad
    NetworkHelper.cs          Deteccion de gateway/Npcap/interfaz
    OuiDatabase.cs            Base embebida de fabricantes (IEEE OUI)
    OsFingerprint.cs          Estimacion de SO por TTL (+ refinado)
  UI/
    MainForm.cs               Ventana principal (tema oscuro)
```

## Compilacion y empaquetado

```powershell
dotnet restore
dotnet build -c Release

# .exe portable (archivo unico, sin necesidad de .NET instalado)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

Resultado: `publish/NetGuardian.exe` (~68 MB). Copialo a cualquier
PC Windows x64 con Npcap y ejecutalo como administrador.

## Como funciona por dentro

### Deteccion de dispositivos
- **Ping sweep** concurrente (64 hilos) sobre la subred /24.
- **Tabla ARP del sistema** (`arp -a`) para las MAC, sin necesidad de
  construir paquetes ARP manualmente.
- **NetBIOS Node Status** (UDP 137): nombre real de los equipos Windows.
- **Zeroconf (nuget: Zeroconf)**: paquete 100% managed (no requiere
  Avahi ni Bonjour ni ningun servicio instalado en el sistema). Funciona en
  dos fases: `BrowseDomainsAsync()` enumera los tipos de servicio anunciados
  en la red (`_workstation._tcp.local`, `_airplay._tcp.local`, etc.) y luego
  `ResolveAsync(tipos)` devuelve los dispositivos concretos (IZeroconfHost:
  DisplayName e IPAddress). `_services._dns-sd._udp.local` solo enumera
  tipos de servicio, no sirve para obtener nombres de dispositivos.
- **mDNS propio** (multicast 224.0.0.251:5353): implementacion interna que
  queda como respaldo por si el paquete falla.
- **OUI**: los 3 primeros bytes de la MAC identifican al fabricante; tambien
  se detectan MACs aleatorias (bit U/L) tipicas de Android/iOS modernos.
- **TTL de las respuestas**: 64 = Linux/Android/iOS, 128 = Windows,
  255 = equipos de red. Se refina combinando con fabricante y NetBIOS.

### Bloqueo y vigilancia
- **Bloqueo**: se envia cada 500 ms un ARP reply que dice a la victima
  "el gateway esta en NUESTRA MAC". Su trafico llega aqui y se descarta.
- **Vigilancia**: se envenena tambien el ARP del gateway ("la victima esta
  en nuestra MAC") y la app **reenvia** cada paquete a su destino real,
  reescribiendo las MAC de la trama Ethernet. La victima mantiene internet
  y todo su trafico es visible y contable.
- Al desbloquear/dejar de vigilar se envian ARP con las MAC reales para
  restaurar ambos extremos.

### Limitacion de velocidad
Ciclos de 1 segundo alternando veneno ARP activo y pausa, en proporcion
al limite elegido. TCP reduce su ventana de congestion solo. Es
aproximado pero no requiere drivers extra (la alternativa precisa es
WinDivert).

## Limitaciones conocidas

- Subred /24 asumida.
- Sin vigilancia activa, en redes conmutadas solo se ve el trafico
  propio/broadcast (por eso el boton "Vigilar trafico").
- El limite de velocidad es aproximado.
- Android/iOS con MAC aleatoria muestran "MAC privada/aleatoria" como
  fabricante.
- El parsing de mDNS es minimalista; si tu red filtra multicast, los
  nombres mDNS no apareceran.
